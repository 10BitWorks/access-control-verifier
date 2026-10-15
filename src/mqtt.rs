//! MQTT integration: decision `cmd` publish, device presence watch, and retained
//! ACL+key distribution for offline-verifying readers.
//!
//! # Accepted risk
//! Devices with `offline_verify=1` receive diversified per-tag keys in the
//! retained `access/{reader}/acl` payload so they can verify SUN CMACs locally
//! when the broker or verifier is unreachable (fail-safe door operation).
//! Physical custody of such a reader therefore implies custody of the tag keys
//! it holds; readers without `offline_verify` never receive key material.

use crate::api::DecisionSink;
use crate::crypto::{diversify, Key, Uid};
use crate::store::{JobClaim, Store};
use crate::writer::{consume_job, job_payload, ConsumeOutcome};
use chrono::{DateTime, Utc};
use rumqttc::{AsyncClient, Event, EventLoop, Incoming, MqttOptions, QoS, Transport};
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};
use std::time::Duration as StdDuration;

const PRESENCE_FILTER: &str = "access/+/presence";
const WRITER_CLAIM_FILTER: &str = "writer/+/claim";
const WRITER_DONE_FILTER: &str = "writer/+/done";
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
                for filter in [PRESENCE_FILTER, WRITER_CLAIM_FILTER, WRITER_DONE_FILTER] {
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
    let uid = match Uid::from_hex(uid_hex) {
        Ok(u) => u,
        Err(_) => {
            tracing::warn!(device, uid_hex, "claim with invalid uid");
            return None;
        }
    };
    let mut store = match store.lock() {
        Ok(s) => s,
        Err(_) => return None,
    };
    match store.claim_job(job_id, uid_hex, now) {
        Ok(JobClaim::Claimed(job)) => {
            let key_hex = hex::encode(diversify(master, &uid).0);
            let payload = job_payload(&job.uid, &key_hex, &job.job_id, &job.expires_at);
            Some((format!("writer/{device}/job"), payload))
        }
        Ok(other) => {
            tracing::debug!(device, job_id, ?other, "claim not granted");
            None
        }
        Err(e) => {
            tracing::warn!(error = %e, device, job_id, "claim_job failed");
            None
        }
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
            let Some((topic, body)) =
                claim_and_build(store, master, device, job_id, &uid_hex, &now)
            else {
                return;
            };
            if let Err(e) = client.publish(topic, QoS::AtLeastOnce, false, body).await {
                tracing::warn!(error = %e, device, job_id, "keyed job publish dropped");
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
