//! MQTT integration: decision `cmd` publish, device presence watch, and retained
//! ACL+key distribution for offline-verifying readers.
//!
//! # Accepted risk
//! Devices with `offline_verify=1` receive diversified per-tag keys in the
//! retained `access/{reader}/acl` payload so they can verify SUN CMACs locally
//! when the broker or verifier is unreachable (fail-safe door operation).
//! Physical custody of such a reader therefore implies custody of the tag keys
//! it holds; readers without `offline_verify` never receive key material.

use crate::api::{reasons, DecisionSink};
use crate::crypto::{diversify, verify_sun, Key, SunCmac, TapCounter, Uid};
use crate::store::{AccessDecision, IngestReportOutcome, JobClaim, Store, TapReportInput};
use crate::sync_projection::split_into_chunks;
use crate::writer::{consume_job, job_payload, ConsumeOutcome};
use chrono::{DateTime, Utc};
use rumqttc::{AsyncClient, Event, EventLoop, Incoming, MqttOptions, QoS, Transport};
use rusqlite::params;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};
use std::time::Duration as StdDuration;

const PRESENCE_FILTER: &str = "access/+/presence";
const WRITER_CLAIM_FILTER: &str = "writer/+/claim";
const WRITER_DONE_FILTER: &str = "writer/+/done";
pub const V2_HELLO_FILTER: &str = "keygate/v2/+/hello";
pub const V2_TAP_FILTER: &str = "keygate/v2/+/tap";
pub const V2_REPORT_FILTER: &str = "keygate/v2/+/report";
const MAX_COUNTER: u64 = 0xFF_FFFF;
const CHANNEL_CAP: usize = 64;
const RECONNECT_DELAY: StdDuration = StdDuration::from_secs(1);
const KEEP_ALIVE: StdDuration = StdDuration::from_secs(30);
const DEFAULT_ACL_EXPIRY_DAYS: i64 = 35;
const DEFAULT_PUSH_PERIOD_MINUTES: u64 = 60;
const TS_FORMAT: &str = "%Y-%m-%dT%H:%M:%SZ";

#[derive(Debug, Clone)]
pub struct MqttConfig {
    pub host: String,
    pub port: u16,
    pub tls: bool,
    pub username: Option<String>,
    pub password: Option<String>,
    pub client_id: String,
}

impl MqttConfig {
    pub fn from_env() -> Self {
        let tls = std::env::var("MQTT_TLS")
            .map(|v| !matches!(v.to_ascii_lowercase().as_str(), "false" | "0"))
            .unwrap_or(true);
        let port = std::env::var("MQTT_PORT")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(if tls { 8883 } else { 1883 });
        Self {
            host: std::env::var("MQTT_HOST").unwrap_or_else(|_| "localhost".to_string()),
            port,
            tls,
            username: std::env::var("MQTT_USERNAME")
                .ok()
                .filter(|v| !v.is_empty()),
            password: std::env::var("MQTT_PASSWORD")
                .ok()
                .filter(|v| !v.is_empty()),
            client_id: std::env::var("MQTT_CLIENT_ID")
                .unwrap_or_else(|_| "access-verifier".to_string()),
        }
    }

    pub fn to_options(&self) -> MqttOptions {
        let mut opts = MqttOptions::new(&self.client_id, &self.host, self.port);
        if self.tls {
            opts.set_transport(Transport::tls_with_default_config());
        } else {
            tracing::warn!("MQTT plaintext transport; acceptable only in development");
        }
        if let (Some(user), Some(pass)) = (&self.username, &self.password) {
            opts.set_credentials(user, pass);
        }
        opts.set_keep_alive(KEEP_ALIVE);
        opts.set_clean_session(true);
        opts
    }
}

#[derive(Clone)]
pub struct MqttSink {
    client: AsyncClient,
}

impl MqttSink {
    pub fn new(client: AsyncClient) -> Self {
        Self { client }
    }
}

impl DecisionSink for MqttSink {
    fn publish_cmd(&self, reader: &str, grant: bool, reason: &str) {
        let topic = format!("access/{reader}/cmd");
        let payload = json!({ "grant": grant, "reason": reason }).to_string();
        if let Err(e) = self
            .client
            .try_publish(topic, QoS::AtLeastOnce, false, payload)
        {
            tracing::warn!(error = %e, reader, "cmd publish dropped");
        }
    }
}

pub struct Spawned {
    pub sink: MqttSink,
    /// Shared client, exposed so a job publisher can reuse the same connection.
    pub client: AsyncClient,
    pub presence_task: tokio::task::JoinHandle<()>,
    pub acl_task: tokio::task::JoinHandle<()>,
}

pub fn spawn(cfg: &MqttConfig, store: Arc<Mutex<Store>>, master: Key) -> Spawned {
    let (client, eventloop) = AsyncClient::new(cfg.to_options(), CHANNEL_CAP);
    let sink = MqttSink {
        client: client.clone(),
    };
    let presence_task = tokio::spawn(run_event_loop(
        eventloop,
        client.clone(),
        Arc::clone(&store),
        master.clone(),
    ));
    let acl_task = tokio::spawn(acl_push_loop(client.clone(), store, master));
    Spawned {
        sink,
        client,
        presence_task,
        acl_task,
    }
}

pub async fn run_event_loop(
    mut eventloop: EventLoop,
    client: AsyncClient,
    store: Arc<Mutex<Store>>,
    master: Key,
) {
    loop {
        match eventloop.poll().await {
            Ok(Event::Incoming(Incoming::ConnAck(_))) => {
                for filter in [
                    PRESENCE_FILTER,
                    WRITER_CLAIM_FILTER,
                    WRITER_DONE_FILTER,
                    V2_HELLO_FILTER,
                    V2_TAP_FILTER,
                    V2_REPORT_FILTER,
                ] {
                    if let Err(e) = client.subscribe(filter, QoS::AtLeastOnce).await {
                        tracing::warn!(error = %e, filter, "subscribe failed");
                    }
                }
            }
            Ok(Event::Incoming(Incoming::Publish(publish))) => {
                if let Some(device) = presence_device(&publish.topic) {
                    handle_presence(&store, device, &publish.payload);
                } else if let Some((device, event)) = writer_event_topic(&publish.topic) {
                    handle_writer(&client, &store, &master, device, event, &publish.payload).await;
                } else if let Some((device, event)) = v2_event_topic(&publish.topic) {
                    handle_v2(&client, &store, &master, device, event, &publish.payload).await;
                }
            }
            Ok(_) => {}
            Err(e) => {
                tracing::warn!(error = %e, "mqtt connection error; reconnecting");
                tokio::time::sleep(RECONNECT_DELAY).await;
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WriterEvent {
    Claim,
    Done,
}

fn writer_event_topic(topic: &str) -> Option<(&str, WriterEvent)> {
    let rest = topic.strip_prefix("writer/")?;
    let (device, kind) = rest.rsplit_once('/')?;
    if device.is_empty() || device.contains('/') {
        return None;
    }
    let event = match kind {
        "claim" => WriterEvent::Claim,
        "done" => WriterEvent::Done,
        _ => return None,
    };
    Some((device, event))
}

/// Outcome of resolving a writer claim.
#[derive(Debug, PartialEq, Eq)]
pub enum ClaimResult {
    /// Claim granted; carries `(topic, payload)` with the keyed job.
    KeyedJob { topic: String, payload: String },
    /// Claim denied with explicit NACK payload for immediate exit from ClaimWait (D12 P-fix-c).
    /// Shape: `{"nack":true,"job_id":...,"reason":"expired|consumed"}`
    Nack { topic: String, payload: String },
    /// Silent ignore (invalid UID, store error, not found, etc.).
    Ignored,
}

/// Build a non-retained NACK payload for a job topic (D12 P-fix-c).
///
/// Published when a device attempts to claim against an expired or consumed job
/// so the device exits `ClaimWait` immediately rather than hanging indefinitely.
pub fn claim_nack_payload(job_id: &str, reason: &str) -> String {
    serde_json::json!({
        "nack": true,
        "job_id": job_id,
        "reason": reason,
    })
    .to_string()
}

/// Resolve a writer claim: either grant with keyed job, NACK on expired/consumed,
/// or ignore on invalid input/not found.
pub fn resolve_claim(
    store: &Arc<Mutex<Store>>,
    master: &Key,
    device: &str,
    job_id: &str,
    uid_hex: &str,
    now: &str,
) -> ClaimResult {
    let uid = match Uid::from_hex(uid_hex) {
        Ok(u) => u,
        Err(_) => {
            tracing::warn!(device, uid_hex, "claim with invalid uid");
            return ClaimResult::Ignored;
        }
    };
    let mut store = match store.lock() {
        Ok(s) => s,
        Err(_) => return ClaimResult::Ignored,
    };
    match store.claim_job_on_device(job_id, uid_hex, now, device) {
        Ok(JobClaim::Claimed(job)) => {
            let key_hex = hex::encode(diversify(master, &uid).0);
            let payload = job_payload(&job.uid, &key_hex, &job.job_id, &job.expires_at);
            ClaimResult::KeyedJob {
                topic: format!("writer/{device}/job"),
                payload,
            }
        }
        Ok(JobClaim::Expired(job)) => {
            tracing::debug!(device, job_id, "claim against expired job; sending NACK");
            ClaimResult::Nack {
                topic: format!("writer/{device}/job"),
                payload: claim_nack_payload(&job.job_id, "expired"),
            }
        }
        Ok(JobClaim::Consumed(job)) => {
            tracing::debug!(device, job_id, "claim against consumed job; sending NACK");
            ClaimResult::Nack {
                topic: format!("writer/{device}/job"),
                payload: claim_nack_payload(&job.job_id, "consumed"),
            }
        }
        Ok(other) => {
            tracing::debug!(device, job_id, ?other, "claim not granted");
            ClaimResult::Ignored
        }
        Err(e) => {
            tracing::warn!(error = %e, device, job_id, "claim_job failed");
            ClaimResult::Ignored
        }
    }
}

/// Bind a wildcard job's uid on first claim and build the keyed delivery
/// payload. Returns `(topic, payload)` only when the claim is granted.
pub fn claim_and_build(
    store: &Arc<Mutex<Store>>,
    master: &Key,
    device: &str,
    job_id: &str,
    uid_hex: &str,
    now: &str,
) -> Option<(String, String)> {
    match resolve_claim(store, master, device, job_id, uid_hex, now) {
        ClaimResult::KeyedJob { topic, payload } => Some((topic, payload)),
        _ => None,
    }
}

async fn handle_writer(
    client: &AsyncClient,
    store: &Arc<Mutex<Store>>,
    master: &Key,
    device: &str,
    event: WriterEvent,
    payload: &[u8],
) {
    let value: Value = match serde_json::from_slice(payload) {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(error = %e, device, "malformed writer payload");
            return;
        }
    };
    let Some(job_id) = value.get("job_id").and_then(|j| j.as_str()) else {
        tracing::warn!(device, "writer payload missing job_id");
        return;
    };
    let now = Utc::now().to_rfc3339();
    match event {
        WriterEvent::Claim => {
            let Some(uid_hex) = value
                .get("uid")
                .and_then(|u| u.as_str())
                .map(|s| s.to_ascii_lowercase())
            else {
                tracing::warn!(device, job_id, "claim payload missing uid");
                return;
            };
            match resolve_claim(store, master, device, job_id, &uid_hex, &now) {
                ClaimResult::KeyedJob { topic, payload } => {
                    if let Err(e) = client
                        .publish(topic, QoS::AtLeastOnce, false, payload)
                        .await
                    {
                        tracing::warn!(error = %e, device, job_id, "keyed job publish dropped");
                    }
                }
                ClaimResult::Nack { topic, payload } => {
                    if let Err(e) = client
                        .publish(topic, QoS::AtLeastOnce, false, payload)
                        .await
                    {
                        tracing::warn!(error = %e, device, job_id, "claim NACK publish dropped");
                    }
                }
                ClaimResult::Ignored => {}
            }
        }
        WriterEvent::Done => {
            let ok = value.get("ok").and_then(|b| b.as_bool()).unwrap_or(false);
            if !ok {
                let reason = value
                    .get("error")
                    .and_then(|e| e.as_str())
                    .unwrap_or("provision_failed");
                if let Ok(mut store) = store.lock() {
                    if let Err(e) = store.fail_job(job_id, &now, reason) {
                        tracing::warn!(error = %e, device, job_id, "fail_job failed");
                    }
                }
                return;
            }
            let counter = value.get("counter").and_then(|c| c.as_u64()).unwrap_or(0);
            if counter > MAX_COUNTER {
                tracing::warn!(device, job_id, counter, "done counter out of range");
                return;
            }
            let outcome = store
                .lock()
                .ok()
                .map(|mut s| consume_job(&mut s, job_id, counter as i64, &now, Some(device)));
            match outcome {
                Some(ConsumeOutcome::Enrolled { uid, .. }) => {
                    tracing::info!(device, job_id, uid, counter, "job enrolled via mqtt")
                }
                Some(other) => tracing::debug!(device, job_id, ?other, "mqtt done not enrolled"),
                None => tracing::warn!(device, job_id, "store lock poisoned on done"),
            }
        }
    }
}

fn presence_device(topic: &str) -> Option<&str> {
    let rest = topic.strip_prefix("access/")?;
    let device = rest.strip_suffix("/presence")?;
    if device.is_empty() || device.contains('/') {
        None
    } else {
        Some(device)
    }
}

fn handle_presence(store: &Arc<Mutex<Store>>, device: &str, payload: &[u8]) {
    let text = String::from_utf8_lossy(payload);
    let online = match text.trim().to_ascii_lowercase().as_str() {
        "online" => true,
        "offline" => false,
        other => {
            tracing::debug!(device, payload = other, "ignoring unknown presence payload");
            return;
        }
    };
    let now = Utc::now().to_rfc3339();
    let mut store = match store.lock() {
        Ok(s) => s,
        Err(_) => return,
    };
    let result = match store.presence_of(device) {
        Ok(Some(previous)) if (previous == "online") == online => {
            store.touch_last_seen(device, &now)
        }
        Ok(_) => store.set_presence(device, online, &now),
        Err(e) => Err(e),
    };
    if let Err(e) = result {
        tracing::warn!(error = %e, device, "presence update failed");
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum V2Event {
    Hello,
    Tap,
    Report,
}

pub fn v2_event_topic(topic: &str) -> Option<(&str, V2Event)> {
    let rest = topic.strip_prefix("keygate/v2/")?;
    let (device, kind) = rest.rsplit_once('/')?;
    if device.is_empty() || device.contains('/') {
        return None;
    }
    let event = match kind {
        "hello" => V2Event::Hello,
        "tap" => V2Event::Tap,
        "report" => V2Event::Report,
        _ => return None,
    };
    Some((device, event))
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct V2HelloPayload {
    pub roster_gen: u64,
    pub key_versions: Vec<i64>,
    pub outbox_depth: u64,
    pub time_uncertain: bool,
    pub git_sha: String,
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct V2TapPayload {
    pub tap_id: String,
    pub uid: String,
    pub counter: u64,
    #[serde(default)]
    pub cmac: Option<String>,
    #[serde(default)]
    pub decision: Option<String>,
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default)]
    pub key_version: Option<i64>,
    #[serde(default)]
    pub time_uncertain: Option<bool>,
    #[serde(default)]
    pub dev_ts: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct V2AckEntry {
    pub uid: String,
    pub status: String,
    pub active_until: Option<String>,
    pub key_version: i64,
    pub entry_gen: i64,
    pub global_counter: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct V2AckPayload {
    pub tap_id: String,
    pub entry: Option<V2AckEntry>,
    pub counter_floor: u64,
    pub time_s: u32,
}

pub fn map_store_reason_to_v2(reason: &str) -> &'static str {
    match reason {
        "ok" | "granted" => reasons::GRANTED,
        "unknown_tag" => reasons::UNKNOWN_TAG,
        "counter_replay" => reasons::COUNTER_REPLAY,
        "counter_saturated" => reasons::COUNTER_SATURATED,
        "expired" | "expired_membership" => reasons::EXPIRED,
        "inactive" | "tag_inactive" | "unknown_member" | "member_inactive" => reasons::INACTIVE,
        "overridden" | "override_ban" => reasons::OVERRIDDEN,
        "bad_cmac" | "cmac_fail" => reasons::CMAC_FAIL,
        "uncommissioned" => reasons::UNCOMMISSIONED,
        _ => reasons::POLICY_DENIED,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RosterGenDivergence {
    InSync,
    NeedsFullSnapshot,
    NeedsDelta { device_gen: u64, config_gen: u64 },
    DeviceAhead { device_gen: u64, config_gen: u64 },
}

pub fn check_roster_gen_divergence(device_gen: u64, config_gen: u64) -> RosterGenDivergence {
    if device_gen == config_gen {
        RosterGenDivergence::InSync
    } else if device_gen == 0 {
        RosterGenDivergence::NeedsFullSnapshot
    } else if device_gen < config_gen {
        RosterGenDivergence::NeedsDelta {
            device_gen,
            config_gen,
        }
    } else {
        RosterGenDivergence::DeviceAhead {
            device_gen,
            config_gen,
        }
    }
}

/// Authoritative flip message published to `keygate/v2/{id}/sync` (Plan D2).
/// Sent after initial roster chunks so the reader transitions from shadow
/// to authoritative local actuation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthoritativeFlipPayload {
    pub authoritative: bool,
}

/// Device status used for dual-master rotation commissioning state check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceHelloStatus {
    pub device_id: String,
    pub offline_verify: bool,
    pub key_versions: Vec<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RotationActivationOutcome {
    Activated {
        new_version: i64,
    },
    WaitingForAcks {
        candidate_version: i64,
        pending_devices: Vec<String>,
    },
}

/// Pure state check for dual-master rotation protocol:
/// Activation of vN+1 requires a hello-echo acknowledging vN+1 from EVERY
/// offline_verify=1 device in the fleet; until all ack, vN remains active.
pub fn check_rotation_activation(
    candidate_version: i64,
    fleet: &[DeviceHelloStatus],
) -> RotationActivationOutcome {
    let offline_devices: Vec<&DeviceHelloStatus> =
        fleet.iter().filter(|d| d.offline_verify).collect();

    let mut pending = Vec::new();
    for dev in &offline_devices {
        if !dev.key_versions.contains(&candidate_version) {
            pending.push(dev.device_id.clone());
        }
    }

    if pending.is_empty() {
        RotationActivationOutcome::Activated {
            new_version: candidate_version,
        }
    } else {
        RotationActivationOutcome::WaitingForAcks {
            candidate_version,
            pending_devices: pending,
        }
    }
}

pub async fn handle_v2(
    client: &AsyncClient,
    store: &Arc<Mutex<Store>>,
    master: &Key,
    device: &str,
    event: V2Event,
    payload: &[u8],
) {
    match event {
        V2Event::Hello => handle_v2_hello(client, store, master, device, payload).await,
        V2Event::Tap | V2Event::Report => {
            handle_v2_tap_or_report(client, store, master, device, event, payload).await
        }
    }
}

struct HelloProcessResult {
    sync_chunks: Vec<Vec<u8>>,
    flip_authoritative: bool,
    commission_payloads: Vec<String>,
}

fn process_v2_hello(
    store: &Arc<Mutex<Store>>,
    master: &Key,
    device: &str,
    hello: &V2HelloPayload,
    now: &str,
) -> Option<HelloProcessResult> {
    let mut s = match store.lock() {
        Ok(s) => s,
        Err(_) => {
            tracing::warn!(device, "store lock poisoned on v2 hello");
            return None;
        }
    };

    match s.presence_of(device) {
        Ok(Some(_)) => {
            if let Err(e) = s.touch_last_seen(device, now) {
                tracing::warn!(error = %e, device, "failed to update last_seen on hello");
            }
        }
        Ok(None) => {
            tracing::warn!(device, "hello received from unregistered/unknown device");
            if let Err(e) = s.set_presence(device, true, now) {
                tracing::warn!(error = %e, device, "failed to register device on hello");
            }
        }
        Err(e) => {
            tracing::warn!(error = %e, device, "failed to check presence of device on hello");
        }
    }

    let is_offline_verify: bool = s
        .conn_mut()
        .query_row(
            "SELECT offline_verify FROM devices WHERE device_id = ?1",
            params![device],
            |r| r.get(0),
        )
        .unwrap_or(0)
        != 0;

    let config_gen: u64 = s
        .get_config("roster_gen")
        .ok()
        .flatten()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(0);

    let divergence = check_roster_gen_divergence(hello.roster_gen, config_gen);

    let mut sync_chunks = Vec::new();
    let mut flip_authoritative = false;

    if divergence != RosterGenDivergence::InSync {
        tracing::info!(
            device,
            device_roster_gen = hello.roster_gen,
            config_roster_gen = config_gen,
            divergence = ?divergence,
            "v2 hello roster_gen divergence => building sync chunks"
        );

        let chunks_to_send = match divergence {
            RosterGenDivergence::NeedsFullSnapshot | RosterGenDivergence::DeviceAhead { .. } => {
                match s.build_full_snapshot() {
                    Ok((gen, entries)) => split_into_chunks(gen, &entries),
                    Err(e) => {
                        tracing::warn!(error = %e, device, "failed to build full snapshot");
                        Vec::new()
                    }
                }
            }
            RosterGenDivergence::NeedsDelta { device_gen, .. } => {
                match s.build_delta_projection(device_gen) {
                    Ok(Some((gen, entries))) => split_into_chunks(gen, &entries),
                    Ok(None) => {
                        tracing::info!(
                            device,
                            device_gen,
                            "delta history evicted; falling back to full snapshot"
                        );
                        match s.build_full_snapshot() {
                            Ok((gen, entries)) => split_into_chunks(gen, &entries),
                            Err(e) => {
                                tracing::warn!(
                                    error = %e,
                                    device,
                                    "failed to build full snapshot fallback"
                                );
                                Vec::new()
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, device, "failed to build delta projection");
                        Vec::new()
                    }
                }
            }
            RosterGenDivergence::InSync => Vec::new(),
        };

        for chunk in chunks_to_send {
            match chunk.encode() {
                Ok(bytes) => sync_chunks.push(bytes),
                Err(e) => tracing::warn!(error = %e, device, "failed to encode sync chunk"),
            }
        }

        if let Err(e) = s.prune_roster_events() {
            tracing::warn!(error = %e, "failed to prune roster_events after projection");
        }

        if is_offline_verify && !sync_chunks.is_empty() {
            flip_authoritative = true;
        }
    }

    // Commissioning: if offline_verify=1, check if hello.key_versions is missing active master keys
    let mut commission_payloads = Vec::new();
    if is_offline_verify {
        let active_key_version = 1i64;
        if !hello.key_versions.contains(&active_key_version) {
            commission_payloads.push(
                json!({
                    "key_version": active_key_version,
                    "master_hex": hex::encode(master.0),
                })
                .to_string(),
            );
        }
    }

    Some(HelloProcessResult {
        sync_chunks,
        flip_authoritative,
        commission_payloads,
    })
}

async fn handle_v2_hello(
    client: &AsyncClient,
    store: &Arc<Mutex<Store>>,
    master: &Key,
    device: &str,
    payload: &[u8],
) {
    let hello: V2HelloPayload = match serde_json::from_slice(payload) {
        Ok(h) => h,
        Err(e) => {
            tracing::warn!(error = %e, device, "malformed v2 hello payload");
            return;
        }
    };
    tracing::info!(
        device,
        roster_gen = hello.roster_gen,
        key_versions = ?hello.key_versions,
        outbox_depth = hello.outbox_depth,
        time_uncertain = hello.time_uncertain,
        git_sha = %hello.git_sha,
        "v2 hello received"
    );

    let now = Utc::now().to_rfc3339();

    // MutexGuard drops before any client.publish().await
    let result = process_v2_hello(store, master, device, &hello, &now);

    let Some(res) = result else {
        return;
    };

    // 1. Publish commissioning if missing key versions
    for comm_json in res.commission_payloads {
        let comm_topic = format!("keygate/v2/{device}/commission");
        if let Err(e) = client
            .publish(comm_topic, QoS::AtLeastOnce, false, comm_json)
            .await
        {
            tracing::warn!(error = %e, device, "failed to publish commission payload");
        }
    }

    // 2. Publish sync chunks sequentially QoS1 non-retained
    let sync_topic = format!("keygate/v2/{device}/sync");
    for chunk_bytes in res.sync_chunks {
        if let Err(e) = client
            .publish(&sync_topic, QoS::AtLeastOnce, false, chunk_bytes)
            .await
        {
            tracing::warn!(error = %e, device, "failed to publish sync chunk");
        }
    }

    // 3. Publish authoritative flip if needed
    if res.flip_authoritative {
        let flip_payload = json!({ "authoritative": true }).to_string();
        if let Err(e) = client
            .publish(&sync_topic, QoS::AtLeastOnce, false, flip_payload)
            .await
        {
            tracing::warn!(error = %e, device, "failed to publish authoritative flip");
        }
    }
}

struct TapProcessResult {
    entry: Option<V2AckEntry>,
    counter_floor: u64,
}

fn process_v2_tap_or_report(
    store: &Arc<Mutex<Store>>,
    device: &str,
    event: V2Event,
    tap: &V2TapPayload,
    uid_hex: &str,
    cmac_valid: bool,
    now_rfc3339: &str,
) -> Option<TapProcessResult> {
    let kind_str = match event {
        V2Event::Tap => "consult",
        V2Event::Report => "report",
        V2Event::Hello => unreachable!(),
    };

    let mut store_guard = match store.lock() {
        Ok(s) => s,
        Err(_) => {
            tracing::warn!(device, tap_id = %tap.tap_id, "store lock poisoned on v2 tap");
            return None;
        }
    };

    let (decision_str, reason_str) = if !cmac_valid {
        ("denied", reasons::CMAC_FAIL)
    } else {
        match store_guard.tag_by_uid(uid_hex) {
            Ok(None) => ("denied", reasons::UNKNOWN_TAG),
            Ok(Some(_)) => {
                if let Some(ref d) = tap.decision {
                    let r = tap.reason.as_deref().unwrap_or(if d == "granted" {
                        reasons::GRANTED
                    } else {
                        reasons::POLICY_DENIED
                    });
                    (d.as_str(), map_store_reason_to_v2(r))
                } else {
                    // Consult: evaluate access using effective_access
                    match store_guard.effective_access(uid_hex, now_rfc3339) {
                        Ok(AccessDecision::Granted) => ("granted", reasons::GRANTED),
                        Ok(AccessDecision::Denied(r)) => ("denied", map_store_reason_to_v2(&r)),
                        Err(e) => {
                            tracing::warn!(error = %e, device, uid = %uid_hex, "effective_access failed");
                            ("denied", reasons::POLICY_DENIED)
                        }
                    }
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, device, uid = %uid_hex, "tag lookup failed");
                ("denied", reasons::POLICY_DENIED)
            }
        }
    };

    // Step (b): Ingest via ingest_tap_report
    let report_input = TapReportInput {
        tap_id: &tap.tap_id,
        device_id: device,
        uid: uid_hex,
        counter: tap.counter as i64,
        decision: Some(decision_str),
        reason: Some(reason_str),
        time_uncertain: tap.time_uncertain.unwrap_or(false),
        dev_ts: tap.dev_ts.as_deref(),
        recv_ts: now_rfc3339,
        key_version: tap.key_version,
        kind: kind_str,
    };

    let ingest_outcome = match store_guard.ingest_tap_report(&report_input) {
        Ok(out) => out,
        Err(e) => {
            tracing::warn!(error = %e, device, tap_id = %tap.tap_id, "ingest_tap_report failed");
            return None;
        }
    };

    // If event == Report, audit-only (never publishes ack)
    if event != V2Event::Tap {
        return None;
    }

    let (entry, counter_floor) = match ingest_outcome {
        IngestReportOutcome::Duplicate(stored) => {
            // Replay stored decision
            let is_invalid = stored.reason.as_deref() == Some(reasons::CMAC_FAIL)
                || stored.reason.as_deref() == Some(reasons::UNKNOWN_TAG)
                || stored.reason.as_deref() == Some("bad_cmac");
            if is_invalid {
                (None, stored.counter as u64)
            } else {
                let tag_row = store_guard.tag_by_uid(uid_hex).ok().flatten();
                let active_until = tag_row.as_ref().and_then(|t| {
                    store_guard
                        .get_member(&t.member_key)
                        .ok()
                        .flatten()
                        .map(|m| m.active_until)
                });
                let floor = tag_row
                    .as_ref()
                    .map(|t| t.last_counter as u64)
                    .unwrap_or(stored.counter as u64);
                let entry = tag_row.map(|t| V2AckEntry {
                    uid: t.uid,
                    status: t.status,
                    active_until,
                    key_version: t.key_version,
                    entry_gen: t.entry_gen,
                    global_counter: t.last_counter,
                });
                (entry, floor)
            }
        }
        IngestReportOutcome::Ingested => {
            if !cmac_valid {
                let floor = store_guard
                    .tag_by_uid(uid_hex)
                    .ok()
                    .flatten()
                    .map(|t| t.last_counter as u64)
                    .unwrap_or(tap.counter);
                (None, floor)
            } else {
                let tag_row = store_guard.tag_by_uid(uid_hex).ok().flatten();
                let active_until = tag_row.as_ref().and_then(|t| {
                    store_guard
                        .get_member(&t.member_key)
                        .ok()
                        .flatten()
                        .map(|m| m.active_until)
                });
                let floor = tag_row
                    .as_ref()
                    .map(|t| t.last_counter as u64)
                    .unwrap_or(tap.counter);
                let entry = tag_row.map(|t| V2AckEntry {
                    uid: t.uid,
                    status: t.status,
                    active_until,
                    key_version: t.key_version,
                    entry_gen: t.entry_gen,
                    global_counter: t.last_counter,
                });
                (entry, floor)
            }
        }
    };

    Some(TapProcessResult {
        entry,
        counter_floor,
    })
}

async fn handle_v2_tap_or_report(
    client: &AsyncClient,
    store: &Arc<Mutex<Store>>,
    master: &Key,
    device: &str,
    event: V2Event,
    payload: &[u8],
) {
    let tap: V2TapPayload = match serde_json::from_slice(payload) {
        Ok(t) => t,
        Err(e) => {
            tracing::warn!(error = %e, device, "malformed v2 tap/report payload");
            return;
        }
    };

    let uid_hex = tap.uid.to_ascii_lowercase();

    // Step (a): CMAC-validate like api.rs:122-131
    // (diversify(master, uid) + verify_sun; invalid => treat as cmac_fail outcome evidence, not a crash)
    let uid_parsed = Uid::from_hex(&uid_hex);
    let cmac_parsed = tap.cmac.as_deref().and_then(|c| SunCmac::from_hex(c).ok());
    let counter_in_range = tap.counter <= MAX_COUNTER;

    let cmac_valid = match (uid_parsed, cmac_parsed, counter_in_range) {
        (Ok(uid), Some(cmac), true) => {
            let tag_key = diversify(master, &uid);
            let tap_counter = TapCounter::from_u32(tap.counter as u32);
            verify_sun(&uid, &tap_counter, &cmac, &tag_key).is_ok()
        }
        _ => false,
    };

    let now_rfc3339 = Utc::now().to_rfc3339();
    let now_epoch_s = Utc::now().timestamp() as u32;

    let Some(result) = process_v2_tap_or_report(
        store,
        device,
        event,
        &tap,
        &uid_hex,
        cmac_valid,
        &now_rfc3339,
    ) else {
        return;
    };

    let ack_payload = V2AckPayload {
        tap_id: tap.tap_id.clone(),
        entry: result.entry,
        counter_floor: result.counter_floor,
        time_s: now_epoch_s,
    };

    let ack_json = match serde_json::to_string(&ack_payload) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(error = %e, device, tap_id = %tap.tap_id, "failed to serialize ack payload");
            return;
        }
    };

    let ack_topic = format!("keygate/v2/{device}/ack");
    if let Err(e) = client
        .publish(ack_topic, QoS::AtLeastOnce, false, ack_json)
        .await
    {
        tracing::warn!(error = %e, device, tap_id = %tap.tap_id, "ack publish dropped");
    }
}

pub async fn acl_push_loop(client: AsyncClient, store: Arc<Mutex<Store>>, master: Key) {
    loop {
        if let Err(e) = push_acls(&client, &store, &master).await {
            tracing::warn!(error = %e, "acl push failed");
        }
        let minutes = store
            .lock()
            .ok()
            .and_then(|s| s.get_config("acl_push_period_minutes").ok().flatten())
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(DEFAULT_PUSH_PERIOD_MINUTES)
            .max(1);
        tokio::time::sleep(StdDuration::from_secs(minutes * 60)).await;
    }
}

pub async fn push_acls(
    client: &AsyncClient,
    store: &Arc<Mutex<Store>>,
    master: &Key,
) -> anyhow::Result<usize> {
    let payload = {
        let store = store.lock().expect("store lock poisoned");
        build_acl(&store, master, Utc::now())?
    };
    let devices = {
        let store = store.lock().expect("store lock poisoned");
        store.acl_devices()?
    };
    let body = payload.to_string();
    for device in &devices {
        let topic = format!("access/{device}/acl");
        client
            .publish(topic, QoS::AtLeastOnce, true, body.clone())
            .await?;
    }
    Ok(devices.len())
}

pub fn build_acl(store: &Store, master: &Key, now: DateTime<Utc>) -> anyhow::Result<Value> {
    let days = store
        .get_config("acl_expiry_days")?
        .as_deref()
        .and_then(|v| v.parse::<i64>().ok())
        .unwrap_or(DEFAULT_ACL_EXPIRY_DAYS);
    let cap = now + chrono::Duration::days(days);
    let mut entries = Vec::new();
    for (uid_hex, active_until) in store.acl_tag_rows()? {
        let Some(active_until) = active_until else {
            continue;
        };
        let Some(active_dt) = parse_ts(&active_until) else {
            tracing::warn!(uid = %uid_hex, "unparseable active_until; excluded from ACL");
            continue;
        };
        if active_dt <= now {
            continue;
        }
        let uid = match Uid::from_hex(&uid_hex) {
            Ok(uid) => uid,
            Err(_) => {
                tracing::warn!(uid = %uid_hex, "invalid uid; excluded from ACL");
                continue;
            }
        };
        let expiry = active_dt.min(cap);
        entries.push(json!({
            "uid": uid_hex,
            "key": hex::encode(diversify(master, &uid).0),
            "expiry": expiry.format(TS_FORMAT).to_string(),
        }));
    }
    Ok(json!({
        "generated_at": now.format(TS_FORMAT).to_string(),
        "entries": entries,
    }))
}

fn parse_ts(s: &str) -> Option<DateTime<Utc>> {
    if let Ok(dt) = DateTime::parse_from_rfc3339(s) {
        return Some(dt.with_timezone(&Utc));
    }
    for fmt in [TS_FORMAT, "%Y-%m-%d %H:%M:%S"] {
        if let Ok(naive) = chrono::NaiveDateTime::parse_from_str(s, fmt) {
            return Some(naive.and_utc());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_v2_event_topic_parser() {
        assert_eq!(
            v2_event_topic("keygate/v2/door1/hello"),
            Some(("door1", V2Event::Hello))
        );
        assert_eq!(
            v2_event_topic("keygate/v2/door-front/tap"),
            Some(("door-front", V2Event::Tap))
        );
        assert_eq!(
            v2_event_topic("keygate/v2/gate9/report"),
            Some(("gate9", V2Event::Report))
        );

        assert_eq!(v2_event_topic("keygate/v2/door1/ack"), None);
        assert_eq!(v2_event_topic("keygate/v2/door1/diag"), None);
        assert_eq!(v2_event_topic("keygate/v2/door1/other"), None);
        assert_eq!(v2_event_topic("keygate/v1/door1/hello"), None);
        assert_eq!(v2_event_topic("access/door1/presence"), None);
        assert_eq!(v2_event_topic("keygate/v2//hello"), None);
        assert_eq!(v2_event_topic("keygate/v2/a/b/hello"), None);
    }

    #[test]
    fn test_v2_hello_payload_serde() {
        let payload = V2HelloPayload {
            roster_gen: 42,
            key_versions: vec![1, 2],
            outbox_depth: 3,
            time_uncertain: false,
            git_sha: "abcdef0".to_string(),
        };
        let json_str = serde_json::to_string(&payload).unwrap();
        let parsed: V2HelloPayload = serde_json::from_str(&json_str).unwrap();
        assert_eq!(parsed.roster_gen, 42);
        assert_eq!(parsed.key_versions, vec![1, 2]);
        assert_eq!(parsed.outbox_depth, 3);
        assert!(!parsed.time_uncertain);
        assert_eq!(parsed.git_sha, "abcdef0");
    }

    #[test]
    fn test_v2_tap_payload_serde_full_and_minimal() {
        // Minimal consult payload (decision and reason null)
        let min_json = r#"{
            "tap_id": "door1:100",
            "uid": "04010203040506",
            "counter": 55,
            "cmac": "0102030405060708"
        }"#;
        let tap: V2TapPayload = serde_json::from_str(min_json).unwrap();
        assert_eq!(tap.tap_id, "door1:100");
        assert_eq!(tap.uid, "04010203040506");
        assert_eq!(tap.counter, 55);
        assert_eq!(tap.cmac.as_deref(), Some("0102030405060708"));
        assert_eq!(tap.decision, None);
        assert_eq!(tap.reason, None);
        assert_eq!(tap.key_version, None);

        // Full payload (outcome report)
        let full_payload = V2TapPayload {
            tap_id: "door1:101".to_string(),
            uid: "04010203040506".to_string(),
            counter: 56,
            cmac: Some("0102030405060708".to_string()),
            decision: Some("granted".to_string()),
            reason: Some("granted".to_string()),
            key_version: Some(1),
            time_uncertain: Some(false),
            dev_ts: Some("2026-10-28T12:00:00Z".to_string()),
        };
        let s = serde_json::to_string(&full_payload).unwrap();
        let de: V2TapPayload = serde_json::from_str(&s).unwrap();
        assert_eq!(de.tap_id, "door1:101");
        assert_eq!(de.decision.as_deref(), Some("granted"));
        assert_eq!(de.reason.as_deref(), Some("granted"));
        assert_eq!(de.key_version, Some(1));
    }

    #[test]
    fn test_v2_ack_payload_serde_entry_null() {
        let ack = V2AckPayload {
            tap_id: "door1:10".to_string(),
            entry: None,
            counter_floor: 123,
            time_s: 1700000000,
        };
        let s = serde_json::to_string(&ack).unwrap();
        let v: Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v["tap_id"], "door1:10");
        assert!(v["entry"].is_null());
        assert_eq!(v["counter_floor"], 123);
        assert_eq!(v["time_s"], 1700000000);

        let parsed: V2AckPayload = serde_json::from_str(&s).unwrap();
        assert_eq!(parsed.entry, None);
    }

    #[test]
    fn test_v2_ack_payload_serde_entry_present() {
        let ack = V2AckPayload {
            tap_id: "door1:11".to_string(),
            entry: Some(V2AckEntry {
                uid: "04010203040506".to_string(),
                status: "active".to_string(),
                active_until: Some("2026-11-01T00:00:00Z".to_string()),
                key_version: 1,
                entry_gen: 5,
                global_counter: 250,
            }),
            counter_floor: 250,
            time_s: 1700000001,
        };
        let s = serde_json::to_string(&ack).unwrap();
        let v: Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v["tap_id"], "door1:11");
        assert_eq!(v["entry"]["uid"], "04010203040506");
        assert_eq!(v["entry"]["status"], "active");
        assert_eq!(v["entry"]["active_until"], "2026-11-01T00:00:00Z");
        assert_eq!(v["entry"]["key_version"], 1);
        assert_eq!(v["entry"]["entry_gen"], 5);
        assert_eq!(v["entry"]["global_counter"], 250);
        assert_eq!(v["counter_floor"], 250);
        assert_eq!(v["time_s"], 1700000001);
    }

    #[test]
    fn test_roster_gen_divergence_logic() {
        assert_eq!(
            check_roster_gen_divergence(10, 10),
            RosterGenDivergence::InSync
        );
        assert_eq!(
            check_roster_gen_divergence(0, 10),
            RosterGenDivergence::NeedsFullSnapshot
        );
        assert_eq!(
            check_roster_gen_divergence(5, 10),
            RosterGenDivergence::NeedsDelta {
                device_gen: 5,
                config_gen: 10
            }
        );
        assert_eq!(
            check_roster_gen_divergence(15, 10),
            RosterGenDivergence::DeviceAhead {
                device_gen: 15,
                config_gen: 10
            }
        );
    }

    #[test]
    fn test_map_store_reason_to_v2_vocabulary() {
        assert_eq!(map_store_reason_to_v2("ok"), reasons::GRANTED);
        assert_eq!(map_store_reason_to_v2("granted"), reasons::GRANTED);
        assert_eq!(map_store_reason_to_v2("unknown_tag"), reasons::UNKNOWN_TAG);
        assert_eq!(
            map_store_reason_to_v2("counter_replay"),
            reasons::COUNTER_REPLAY
        );
        assert_eq!(
            map_store_reason_to_v2("counter_saturated"),
            reasons::COUNTER_SATURATED
        );
        assert_eq!(map_store_reason_to_v2("expired"), reasons::EXPIRED);
        assert_eq!(
            map_store_reason_to_v2("expired_membership"),
            reasons::EXPIRED
        );
        assert_eq!(map_store_reason_to_v2("tag_inactive"), reasons::INACTIVE);
        assert_eq!(map_store_reason_to_v2("inactive"), reasons::INACTIVE);
        assert_eq!(map_store_reason_to_v2("override_ban"), reasons::OVERRIDDEN);
        assert_eq!(map_store_reason_to_v2("cmac_fail"), reasons::CMAC_FAIL);
        assert_eq!(map_store_reason_to_v2("bad_cmac"), reasons::CMAC_FAIL);
        assert_eq!(
            map_store_reason_to_v2("uncommissioned"),
            reasons::UNCOMMISSIONED
        );
        assert_eq!(
            map_store_reason_to_v2("other_reason"),
            reasons::POLICY_DENIED
        );
    }
}
