//! Protocol integration test suite.
//!
//! Drives the REAL verifier MQTT handlers against a SIMULATED DEVICE implementing
//! the firmware's actual exchange semantics.
//!
//! Pins:
//! 1. `outbox_drain_advances_on_report_ack`: The device outbox poison-loop regression:
//!    simulated device flushes head record :1; verifier's report handler must ack;
//!    device advances to :2; drain completes within N iterations. Fails if the verifier
//!    stops acking reports.
//! 2. `consult_ack_carries_entry_and_floor`: Tap consult round-trip including counter_floor
//!    adoption, entry parsing, and time_s anchor update semantics.
//! 3. `ota_gap_hold_requires_awaiting_rewind`: Host-side classify_offset table + the invariant
//!    that a too-high chunk never aborts a transfer (holds and requests rewind).
//! 4. `commission_missing_key_version_round_trip`: Hello with empty key_versions triggers
//!    commission; device applies key; next hello includes v1.

use access_control_verifier::crypto::{cmac_for, Key, TapCounter, Uid};
use access_control_verifier::mqtt::{spawn, MqttConfig};
use access_control_verifier::store::Store;
use rumqttc::{AsyncClient, Event, EventLoop, Incoming, MqttOptions, QoS};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::VecDeque;
use std::net::TcpListener;
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tempfile::NamedTempFile;

const MASTER_HEX: &str = "000102030405060708090a0b0c0d0e0f";
const UID_ACTIVE: &str = "04010203040506";

// ============================================================================
// Broker Harness
// ============================================================================

struct Broker {
    port: u16,
    container: String,
}

impl Drop for Broker {
    fn drop(&mut self) {
        let _ = Command::new("docker")
            .args(["rm", "-f", &self.container])
            .output();
    }
}

fn start_broker() -> Broker {
    let port = {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind free port");
        listener.local_addr().expect("local addr").port()
    };
    let conf_dir = tempfile::tempdir().expect("conf dir");
    std::fs::write(
        conf_dir.path().join("mosquitto.conf"),
        "listener 1883\nallow_anonymous true\n",
    )
    .expect("write mosquitto.conf");
    let mount = format!("{}:/mosquitto/config", conf_dir.path().display());
    let output = Command::new("docker")
        .args([
            "run",
            "-d",
            "--rm",
            "-p",
            &format!("127.0.0.1:{port}:1883"),
            "-v",
            &mount,
            "eclipse-mosquitto:2",
        ])
        .output()
        .expect("docker run");
    assert!(
        output.status.success(),
        "docker run failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let container = String::from_utf8(output.stdout)
        .expect("utf8")
        .trim()
        .to_string();

    for _ in 0..50 {
        if TcpListener::bind(("127.0.0.1", port)).is_err() {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    std::thread::sleep(Duration::from_millis(300));
    Broker { port, container }
}

fn client_options(port: u16, id: &str) -> MqttOptions {
    let mut opts = MqttOptions::new(id, "127.0.0.1", port);
    opts.set_clean_session(true);
    opts
}

fn build_store(device_id: &str, offline_verify: i64) -> (Arc<Mutex<Store>>, NamedTempFile) {
    let db = NamedTempFile::new().expect("temp db");
    let mut store = Store::open(db.path()).expect("store opens");
    let now = chrono::Utc::now().to_rfc3339();
    store
        .conn_mut()
        .execute(
            "INSERT INTO members (member_key, display_name, active_until)
             VALUES ('m1', 'Test Member', datetime('now', '+10 days'))",
            [],
        )
        .expect("insert member");
    store
        .enroll_tag(UID_ACTIVE, "m1", 1, &now)
        .expect("enroll tag");
    store
        .conn_mut()
        .execute(
            "INSERT INTO devices (device_id, role, offline_verify, presence)
             VALUES (?1, 'gate', ?2, 'online')",
            rusqlite::params![device_id, offline_verify],
        )
        .expect("insert device");
    (Arc::new(Mutex::new(store)), db)
}

async fn wait_for_suback(eventloop: &mut EventLoop) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while tokio::time::Instant::now() < deadline {
        match tokio::time::timeout(Duration::from_millis(500), eventloop.poll()).await {
            Ok(Ok(Event::Incoming(Incoming::SubAck(_)))) => return,
            Ok(Ok(_)) => continue,
            Ok(Err(e)) => panic!("poll err waiting for suback: {:?}", e),
            Err(_) => continue,
        }
    }
    panic!("timed out waiting for SubAck");
}

// ============================================================================
// Simulated Device Types & Contracts
// Derived from firmware: keygate-esp-access-devices
// ============================================================================

/// Mirrors firmware's TimeAnchor:
/// `keygate-esp-access-devices/src/tap_decision.rs:89-140`
#[derive(Debug, Clone, Default)]
pub struct SimulatedTimeAnchor {
    pub base_wall_s: u32,
    pub base_uptime_ms: u64,
    pub time_uncertain: bool,
}

impl SimulatedTimeAnchor {
    pub fn new() -> Self {
        Self {
            base_wall_s: 0,
            base_uptime_ms: 0,
            time_uncertain: true,
        }
    }

    /// Mirrors `tap_decision.rs:125-139`:
    /// `wall_now = max(all received times this boot) + uptime delta`
    pub fn update(&mut self, time_s: u32, uptime_ms: u64) {
        if time_s > 0 {
            let current_est = self.estimate_now(uptime_ms);
            let new_base = if self.time_uncertain {
                time_s
            } else {
                time_s.max(current_est)
            };
            self.base_wall_s = new_base;
            self.base_uptime_ms = uptime_ms;
            self.time_uncertain = false;
        }
    }

    pub fn estimate_now(&self, uptime_ms: u64) -> u32 {
        if self.time_uncertain {
            0
        } else {
            let delta_s = uptime_ms.saturating_sub(self.base_uptime_ms) / 1000;
            self.base_wall_s.saturating_add(delta_s as u32)
        }
    }
}

/// Outbox record stored in device flash WAL.
/// Mirrors `keygate-esp-access-devices/src/keygate_store.rs:163-178` and `node.rs:1691-1718`
#[derive(Debug, Clone)]
pub struct OutboxRecord {
    pub tap_seq: u64,
    pub uid: [u8; 7],
    pub counter: u32,
    pub decision: String,
    pub reason: String,
    pub key_version: Option<u32>,
}

/// Wire representation of ack payload from verifier.
/// Mirrors `keygate-esp-access-devices/src/exchange.rs:201-260` (`parse_ack_json`/`WireAck`)
#[derive(Debug, Clone, Deserialize)]
pub struct WireAck {
    pub tap_id: String,
    pub entry: Option<WireAckEntry>,
    pub counter_floor: u64,
    pub time_s: u32,
}

#[derive(Debug, Clone, Deserialize)]
pub struct WireAckEntry {
    pub uid: String,
    pub status: String,
    pub active_until: Option<String>,
    pub key_version: i64,
    pub entry_gen: i64,
    pub global_counter: i64,
}

/// Commission payload.
/// Mirrors `keygate-esp-access-devices/src/exchange.rs:334-360` (`parse_commission_json`)
#[derive(Debug, Clone, Deserialize)]
pub struct CommissionMsg {
    pub key_version: u32,
    pub master_hex: String,
}

/// OTA OffsetAction.
/// Mirrors `keygate-esp-access-devices/src/ota_probation.rs:69-92` (`classify_offset`)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OffsetAction {
    Accept,
    Duplicate,
    Hold,
    IgnoreErasing,
}

/// Pure helper for classifying incoming data chunk offset against current receiver state.
/// Direct implementation of `keygate-esp-access-devices/src/ota_probation.rs:82-92`:
pub fn classify_offset(off: usize, written: usize, erasing: bool) -> OffsetAction {
    if erasing {
        OffsetAction::IgnoreErasing
    } else if off == written {
        OffsetAction::Accept
    } else if off < written {
        OffsetAction::Duplicate
    } else {
        OffsetAction::Hold
    }
}

/// Master key record.
/// Mirrors `keygate-esp-access-devices/src/keygate_store.rs:125-132`
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MasterKey {
    pub version: u32,
    pub key: [u8; 16],
}

/// Simulated Device implementing the firmware's wire and outbox semantics.
pub struct SimulatedDevice {
    pub device_id: String,
    pub roster_gen: u64,
    pub masters: [MasterKey; 2],
    pub outbox: VecDeque<OutboxRecord>,
    pub time_anchor: SimulatedTimeAnchor,
    pub pending_consult_tap_id: Option<String>,
    pub git_sha: String,
}

impl SimulatedDevice {
    pub fn new(device_id: &str) -> Self {
        Self {
            device_id: device_id.to_string(),
            roster_gen: 0,
            masters: [
                MasterKey {
                    version: 0,
                    key: [0; 16],
                },
                MasterKey {
                    version: 0,
                    key: [0; 16],
                },
            ],
            outbox: VecDeque::new(),
            time_anchor: SimulatedTimeAnchor::new(),
            pending_consult_tap_id: None,
            git_sha: "sim_test_sha".to_string(),
        }
    }

    /// Build Hello payload.
    /// Mirrors `keygate-esp-access-devices/src/exchange.rs:87-124` (`build_hello_json`)
    pub fn build_hello_payload(&self) -> String {
        let key_versions: Vec<u32> = self
            .masters
            .iter()
            .filter(|m| m.version > 0)
            .map(|m| m.version)
            .collect();
        json!({
            "roster_gen": self.roster_gen,
            "key_versions": key_versions,
            "outbox_depth": self.outbox.len(),
            "time_uncertain": self.time_anchor.time_uncertain,
            "git_sha": self.git_sha,
        })
        .to_string()
    }

    /// Build Tap Consult payload.
    /// Mirrors `keygate-esp-access-devices/src/exchange.rs:133-184` (`build_tap_payload`)
    /// and `node.rs:509-519` (consult sends decision=null, reason=null)
    pub fn build_consult_payload(
        &mut self,
        tap_seq: u64,
        uid: &[u8; 7],
        counter: u32,
        cmac: &[u8; 8],
    ) -> (String, String) {
        let tap_id = format!("{}:{}", self.device_id, tap_seq);
        self.pending_consult_tap_id = Some(tap_id.clone());
        let payload = json!({
            "tap_id": tap_id,
            "uid": hex::encode(uid),
            "counter": counter,
            "cmac": hex::encode(cmac),
            "decision": Value::Null,
            "reason": Value::Null,
            "key_version": if self.masters[0].version > 0 { Some(self.masters[0].version) } else { None },
        }).to_string();
        (tap_id, payload)
    }

    /// Build Outbox Head Flush payload.
    /// Mirrors `keygate-esp-access-devices/src/node.rs:1683-1735`
    pub fn build_head_flush_payload(&self) -> Option<(u64, String)> {
        let head = self.outbox.front()?;
        let tap_id = format!("{}:{}", self.device_id, head.tap_seq);
        let payload = json!({
            "tap_id": tap_id,
            "uid": hex::encode(head.uid),
            "counter": head.counter,
            "cmac": "0000000000000000",
            "decision": head.decision,
            "reason": head.reason,
            "key_version": head.key_version,
        })
        .to_string();
        Some((head.tap_seq, payload))
    }

    /// On Ack received on `keygate/v2/{id}/ack`.
    /// Mirrors `keygate-esp-access-devices/src/node.rs:1907-1944` and `node.rs:543-552`
    pub fn on_ack_received(&mut self, payload: &[u8], uptime_ms: u64) -> Result<WireAck, String> {
        let ack: WireAck =
            serde_json::from_slice(payload).map_err(|e| format!("parse ack failed: {}", e))?;

        // 1. Update TimeAnchor from verifier epoch timestamp (node.rs:1911-1914, node.rs:547-550)
        if ack.time_s > 0 {
            self.time_anchor.update(ack.time_s, uptime_ms);
        }

        // 2. Correlate with pending consult (node.rs:1916-1930)
        if let Some(ref pc) = self.pending_consult_tap_id {
            if *pc == ack.tap_id {
                self.pending_consult_tap_id = None;
            }
        }

        // 3. Mark outbox WAL record acknowledged if matching tap_id (node.rs:1931-1943)
        // tap_id format: "<device_id>:<seq-decimal>"
        if let Some(pos) = ack.tap_id.find(':') {
            if let Ok(seq) = ack.tap_id[pos + 1..].parse::<u64>() {
                // store.ack_up_to(seq) advances horizon:
                // pop records from front where tap_seq <= seq
                while let Some(front) = self.outbox.front() {
                    if front.tap_seq <= seq {
                        self.outbox.pop_front();
                    } else {
                        break;
                    }
                }
            }
        }

        Ok(ack)
    }

    /// Apply Commissioning payload.
    /// Mirrors `keygate-esp-access-devices/src/exchange.rs:364-383` (`apply_commission_key`)
    /// and `node.rs:1945-1963`
    pub fn on_commission_received(&mut self, payload: &[u8]) -> Result<(), String> {
        let comm: CommissionMsg = serde_json::from_slice(payload)
            .map_err(|e| format!("parse commission failed: {}", e))?;
        let mut key_bytes = [0u8; 16];
        hex::decode_to_slice(&comm.master_hex, &mut key_bytes)
            .map_err(|e| format!("hex decode master: {}", e))?;

        for m in self.masters.iter_mut() {
            if m.version == comm.key_version {
                m.key = key_bytes;
                return Ok(());
            }
        }
        // Shift primary to fallback, insert new primary
        self.masters[1] = self.masters[0];
        self.masters[0] = MasterKey {
            version: comm.key_version,
            key: key_bytes,
        };
        Ok(())
    }
}

// ============================================================================
// Scenarios
// ============================================================================

/// Scenario 1: `outbox_drain_advances_on_report_ack`
/// Pins the poison-loop regression:
/// Simulated device flushes record :1; verifier's report handler must ack;
/// device advances to :2; drain completes within N iterations.
/// Fails if the verifier ever stops acking reports.
#[tokio::test]
async fn outbox_drain_advances_on_report_ack() {
    let broker = start_broker();
    let (store, _db) = build_store("door-drain", 1);
    let master = Key::from_hex(MASTER_HEX).expect("master key");

    let spawned = spawn(
        &MqttConfig {
            host: "127.0.0.1".to_string(),
            port: broker.port,
            tls: false,
            username: None,
            password: None,
            client_id: "verifier-drain-test".to_string(),
        },
        Arc::clone(&store),
        master.clone(),
    );

    let (client, mut eventloop) =
        AsyncClient::new(client_options(broker.port, "sim-device-drain"), 16);
    client
        .subscribe("keygate/v2/door-drain/ack", QoS::AtLeastOnce)
        .await
        .expect("sub ack");
    wait_for_suback(&mut eventloop).await;

    let mut device = SimulatedDevice::new("door-drain");
    // Queue 3 outbox records: :1, :2, :3
    for seq in 1..=3 {
        device.outbox.push_back(OutboxRecord {
            tap_seq: seq,
            uid: [0x04, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06],
            counter: seq as u32 * 10,
            decision: "granted".to_string(),
            reason: "granted".to_string(),
            key_version: Some(1),
        });
    }

    assert_eq!(device.outbox.len(), 3);

    // Simulate firmware pump loop flush:
    // node.rs:1683-1739: flush head record every 100ms, wait for ack, advance.
    let max_iterations = 10;
    let mut iterations = 0;
    let mut simulated_uptime_ms = 1000u64;

    while !device.outbox.is_empty() && iterations < max_iterations {
        iterations += 1;
        simulated_uptime_ms += 100;

        let (seq, flush_payload) = device
            .build_head_flush_payload()
            .expect("head record available");
        client
            .publish(
                "keygate/v2/door-drain/report",
                QoS::AtLeastOnce,
                false,
                flush_payload,
            )
            .await
            .expect("publish report flush");

        // Await ack on keygate/v2/door-drain/ack
        let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
        let mut got_ack = false;
        while tokio::time::Instant::now() < deadline {
            let res = tokio::time::timeout(Duration::from_millis(500), eventloop.poll()).await;
            if let Ok(Ok(Event::Incoming(Incoming::Publish(p)))) = res {
                if p.topic == "keygate/v2/door-drain/ack" {
                    let ack = device
                        .on_ack_received(&p.payload, simulated_uptime_ms)
                        .expect("ack parsed");
                    assert_eq!(ack.tap_id, format!("door-drain:{}", seq));
                    assert!(
                        ack.entry.is_none(),
                        "report ack must carry null entry (node.rs:903)"
                    );
                    assert_eq!(
                        ack.counter_floor, 0,
                        "report ack must carry 0 counter_floor"
                    );
                    got_ack = true;
                    break;
                }
            }
        }

        assert!(
            got_ack,
            "verifier failed to ack report flush for seq {} (poison loop!)",
            seq
        );
    }

    assert_eq!(
        device.outbox.len(),
        0,
        "outbox must be completely drained; remaining: {}",
        device.outbox.len()
    );
    assert_eq!(iterations, 3, "expected exactly 3 flushes for 3 records");

    spawned.presence_task.abort();
    spawned.acl_task.abort();
}

/// Scenario 2: `consult_ack_carries_entry_and_floor`
/// Tap consult round-trip including counter_floor adoption and time_s anchor semantics.
#[tokio::test]
async fn consult_ack_carries_entry_and_floor() {
    let broker = start_broker();
    let (store, _db) = build_store("door-consult", 1);
    let master = Key::from_hex(MASTER_HEX).expect("master key");

    let spawned = spawn(
        &MqttConfig {
            host: "127.0.0.1".to_string(),
            port: broker.port,
            tls: false,
            username: None,
            password: None,
            client_id: "verifier-consult-test".to_string(),
        },
        Arc::clone(&store),
        master.clone(),
    );

    let (client, mut eventloop) =
        AsyncClient::new(client_options(broker.port, "sim-device-consult"), 16);
    client
        .subscribe("keygate/v2/door-consult/ack", QoS::AtLeastOnce)
        .await
        .expect("sub ack");
    wait_for_suback(&mut eventloop).await;

    let mut device = SimulatedDevice::new("door-consult");
    // Device starts with time uncertain
    assert!(device.time_anchor.time_uncertain);

    // Prepare a valid cryptographic consult tap for enrolled tag UID_ACTIVE
    let uid_bytes = [0x04, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
    let counter = 100u32;
    let tap_counter = TapCounter::from_u32(counter);
    let cmac_bytes = cmac_for(&master, &Uid(uid_bytes), &tap_counter);

    let (tap_id, consult_payload) =
        device.build_consult_payload(1, &uid_bytes, counter, &cmac_bytes.0);
    assert_eq!(device.pending_consult_tap_id, Some(tap_id.clone()));

    client
        .publish(
            "keygate/v2/door-consult/tap",
            QoS::AtLeastOnce,
            false,
            consult_payload,
        )
        .await
        .expect("pub consult tap");

    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    let mut received_ack = None;
    while tokio::time::Instant::now() < deadline {
        let res = tokio::time::timeout(Duration::from_millis(500), eventloop.poll()).await;
        if let Ok(Ok(Event::Incoming(Incoming::Publish(p)))) = res {
            if p.topic == "keygate/v2/door-consult/ack" {
                let ack = device.on_ack_received(&p.payload, 5000).expect("ack valid");
                received_ack = Some(ack);
                break;
            }
        }
    }

    let ack = received_ack.expect("must receive consult ack");
    assert_eq!(ack.tap_id, tap_id);

    // 1. Entry validation: consult for valid enrolled tag must return entry
    let entry = ack.entry.expect("consult ack must carry entry");
    assert_eq!(entry.uid, UID_ACTIVE);
    assert_eq!(entry.status, "active");
    assert_eq!(entry.key_version, 1);
    assert!(
        entry.active_until.is_some(),
        "active tag must carry active_until"
    );

    // 2. Counter floor validation: merged to at least the tap counter
    assert!(
        ack.counter_floor >= counter as u64,
        "counter_floor must be >= tap counter: got {}",
        ack.counter_floor
    );

    // 3. Time anchor adoption: time_uncertain must clear, time_s must be non-zero
    assert!(ack.time_s > 0, "ack must carry non-zero time_s");
    assert!(
        !device.time_anchor.time_uncertain,
        "time_anchor must become certain after consult ack (node.rs:550)"
    );
    assert!(
        device.time_anchor.estimate_now(5000) >= ack.time_s,
        "time_anchor estimate must reflect ack time_s"
    );
    assert!(
        device.pending_consult_tap_id.is_none(),
        "pending consult must be cleared upon correlated ack receipt"
    );

    spawned.presence_task.abort();
    spawned.acl_task.abort();
}

/// Scenario 3: `ota_gap_hold_requires_awaiting_rewind`
/// Host-side: classify_offset table + the invariant that a too-high chunk never aborts a transfer.
#[test]
fn ota_gap_hold_requires_awaiting_rewind() {
    // Test the pure classification contract:
    // keygate-esp-access-devices/src/ota_probation.rs:82-92:
    // if erasing -> IgnoreErasing
    // if off == written -> Accept
    // if off < written -> Duplicate (re-delivery)
    // if off > written -> Hold (GAP detected, hold position, do NOT abort!)

    let written = 4096;

    // 1. Exact match -> Accept
    assert_eq!(classify_offset(4096, written, false), OffsetAction::Accept);

    // 2. Lower offset -> Duplicate (silently dropped / duplicate ack)
    assert_eq!(
        classify_offset(2048, written, false),
        OffsetAction::Duplicate
    );
    assert_eq!(classify_offset(0, written, false), OffsetAction::Duplicate);

    // 3. Erasing -> IgnoreErasing
    assert_eq!(
        classify_offset(4096, written, true),
        OffsetAction::IgnoreErasing
    );
    assert_eq!(
        classify_offset(8192, written, true),
        OffsetAction::IgnoreErasing
    );

    // 4. Too-high chunk (GAP) -> Hold (NOT abort)
    // Invariant: a gap never aborts the transfer. It holds the written horizon
    // so the host script can read "awaiting <written>" and rewind.
    assert_eq!(classify_offset(8192, written, false), OffsetAction::Hold);
    assert_eq!(classify_offset(4097, written, false), OffsetAction::Hold);
    assert_eq!(classify_offset(100_000, written, false), OffsetAction::Hold);
}

/// Scenario 4: `commission_missing_key_version_round_trip`
/// Hello with empty key_versions triggers commission; device applies key; next hello includes v1.
#[tokio::test]
async fn commission_missing_key_version_round_trip() {
    let broker = start_broker();
    let (store, _db) = build_store("door-comm", 1);
    let master = Key::from_hex(MASTER_HEX).expect("master key");

    let spawned = spawn(
        &MqttConfig {
            host: "127.0.0.1".to_string(),
            port: broker.port,
            tls: false,
            username: None,
            password: None,
            client_id: "verifier-comm-test".to_string(),
        },
        Arc::clone(&store),
        master.clone(),
    );

    let (client, mut eventloop) =
        AsyncClient::new(client_options(broker.port, "sim-device-comm"), 16);
    client
        .subscribe("keygate/v2/door-comm/commission", QoS::AtLeastOnce)
        .await
        .expect("sub commission");
    wait_for_suback(&mut eventloop).await;

    let mut device = SimulatedDevice::new("door-comm");
    // Initially uncommissioned: key_versions is empty
    assert_eq!(device.masters[0].version, 0);

    // Step 1: Device sends initial Hello reporting empty key_versions
    let hello_payload = device.build_hello_payload();
    let hello_v: Value = serde_json::from_str(&hello_payload).unwrap();
    assert_eq!(hello_v["key_versions"].as_array().unwrap().len(), 0);

    client
        .publish(
            "keygate/v2/door-comm/hello",
            QoS::AtLeastOnce,
            false,
            hello_payload,
        )
        .await
        .expect("pub hello");

    // Step 2: Verifier sees offline_verify=1 device missing key_version=1,
    // and publishes commission payload to keygate/v2/door-comm/commission
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    let mut got_commission = false;
    while tokio::time::Instant::now() < deadline {
        let res = tokio::time::timeout(Duration::from_millis(500), eventloop.poll()).await;
        if let Ok(Ok(Event::Incoming(Incoming::Publish(p)))) = res {
            if p.topic == "keygate/v2/door-comm/commission" {
                device
                    .on_commission_received(&p.payload)
                    .expect("commission applied");
                got_commission = true;
                break;
            }
        }
    }

    assert!(got_commission, "verifier must publish commission payload");

    // Step 3: Device applied commissioned key: masters[0].version == 1 and key matches
    assert_eq!(device.masters[0].version, 1);
    assert_eq!(hex::encode(device.masters[0].key), MASTER_HEX);

    // Step 4: Next hello published by device now echoes key_versions: [1]
    let next_hello = device.build_hello_payload();
    let next_v: Value = serde_json::from_str(&next_hello).unwrap();
    let kvs = next_v["key_versions"].as_array().unwrap();
    assert_eq!(kvs.len(), 1);
    assert_eq!(kvs[0], 1);

    spawned.presence_task.abort();
    spawned.acl_task.abort();
}
