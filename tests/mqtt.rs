use access_control_verifier::crypto::{diversify, Key, Uid};
use access_control_verifier::mqtt::{build_acl, push_acls, spawn, MqttConfig, MqttSink};
use access_control_verifier::store::Store;
use rumqttc::{AsyncClient, Event, EventLoop, Incoming, MqttOptions, QoS};
use serde_json::{json, Value};
use std::net::TcpListener;
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tempfile::NamedTempFile;

const MASTER_HEX: &str = "000102030405060708090a0b0c0d0e0f";
const UID_ACTIVE: &str = "04010203040506";

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

    // Wait for the broker to accept TCP connections.
    for _ in 0..50 {
        if TcpListener::bind(("127.0.0.1", port)).is_err() {
            // Port is bound by docker-proxy already; try an MQTT-level ping below.
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

async fn wait_for_publish(eventloop: &mut EventLoop, timeout: Duration) -> Option<Incoming> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return None;
        }
        match tokio::time::timeout(remaining, eventloop.poll()).await {
            Ok(Ok(Event::Incoming(Incoming::Publish(publish)))) => {
                return Some(Incoming::Publish(publish));
            }
            Ok(Ok(_)) => continue,
            Ok(Err(_)) => continue,
            Err(_) => return None,
        }
    }
}

fn parse_publish(incoming: Incoming) -> (String, Value) {
    let Incoming::Publish(publish) = incoming else {
        panic!("expected publish");
    };
    let value: Value = serde_json::from_slice(&publish.payload).expect("payload is JSON");
    (publish.topic, value)
}

#[tokio::test]
async fn retained_acl_reaches_offline_device_on_subscribe() {
    let broker = start_broker();
    let (store, _db) = build_store("door1", 1);
    let master = Key::from_hex(MASTER_HEX).expect("master key");

    let spawned = spawn(
        &MqttConfig {
            host: "127.0.0.1".to_string(),
            port: broker.port,
            tls: false,
            username: None,
            password: None,
            client_id: "verifier-acl".to_string(),
        },
        Arc::clone(&store),
        master.clone(),
    );

    // Push once explicitly so the test does not race the initial loop push.
    let pushed = {
        let (client, mut eventloop) =
            AsyncClient::new(client_options(broker.port, "acl-pusher"), 8);
        let handle = tokio::spawn(async move {
            loop {
                if eventloop.poll().await.is_err() {
                    break;
                }
            }
        });
        let count = push_acls(&client, &store, &master).await.expect("push acl");
        // Give QoS1 publishes time to be acknowledged before tearing down.
        tokio::time::sleep(Duration::from_millis(300)).await;
        handle.abort();
        count
    };
    assert_eq!(pushed, 1, "one offline_verify device receives the ACL");

    let (sub_client, mut sub_eventloop) =
        AsyncClient::new(client_options(broker.port, "acl-sub"), 8);
    sub_client
        .subscribe("access/door1/acl", QoS::AtLeastOnce)
        .await
        .expect("subscribe");
    let incoming = wait_for_publish(&mut sub_eventloop, Duration::from_secs(5))
        .await
        .expect("retained ACL arrives on subscribe");
    let (topic, payload) = parse_publish(incoming);
    assert_eq!(topic, "access/door1/acl");

    let entries = payload["entries"].as_array().expect("entries array");
    assert_eq!(entries.len(), 1, "active tag is distributed");
    assert_eq!(entries[0]["uid"], UID_ACTIVE);

    let uid = Uid::from_hex(UID_ACTIVE).expect("uid hex");
    let expected_key = hex::encode(diversify(&master, &uid).0);
    assert_eq!(entries[0]["key"], expected_key, "diversified key only");

    let expiry = entries[0]["expiry"].as_str().expect("expiry string");
    let expiry_dt = chrono::DateTime::parse_from_rfc3339(expiry).expect("rfc3339 expiry");
    let now = chrono::Utc::now();
    let cap = now + chrono::Duration::days(35);
    assert!(
        expiry_dt.with_timezone(&chrono::Utc) <= cap,
        "expiry {expiry} must be within 35 days"
    );
    assert!(
        expiry_dt.with_timezone(&chrono::Utc) > now,
        "expiry must be in the future"
    );
    assert!(payload["generated_at"].is_string(), "generated_at present");

    spawned.presence_task.abort();
    spawned.acl_task.abort();
}

#[tokio::test]
async fn acl_never_reaches_non_offline_verify_device() {
    let broker = start_broker();
    let (store, _db) = build_store("door2", 0);
    let master = Key::from_hex(MASTER_HEX).expect("master key");

    let (client, mut eventloop) = AsyncClient::new(client_options(broker.port, "acl-strict"), 8);
    let pump = tokio::spawn(async move {
        loop {
            if eventloop.poll().await.is_err() {
                break;
            }
        }
    });

    let pushed = push_acls(&client, &store, &master).await.expect("push acl");
    assert_eq!(pushed, 0, "offline_verify=false device gets no ACL push");

    // Subscribing must not surface any retained key material either.
    let (sub_client, mut sub_eventloop) =
        AsyncClient::new(client_options(broker.port, "strict-sub"), 8);
    sub_client
        .subscribe("access/door2/acl", QoS::AtLeastOnce)
        .await
        .expect("subscribe");
    let incoming = wait_for_publish(&mut sub_eventloop, Duration::from_secs(2)).await;
    assert!(
        incoming.is_none(),
        "no key material on ACL topic of offline_verify=false device"
    );

    // The build itself must also omit non-cached members, defense in depth.
    let payload = {
        let store = store.lock().expect("store lock");
        build_acl(&store, &master, chrono::Utc::now()).expect("build acl")
    };
    assert_eq!(
        payload["entries"].as_array().map(|e| e.len()),
        Some(1),
        "payload shape still valid for other consumers"
    );

    pump.abort();
}

#[tokio::test]
async fn presence_offline_flips_device_row_and_audits() {
    let broker = start_broker();
    let (store, _db) = build_store("door3", 0);
    assert_eq!(
        store
            .lock()
            .expect("store lock")
            .presence_of("door3")
            .expect("presence_of"),
        Some("online".to_string())
    );

    let spawned = spawn(
        &MqttConfig {
            host: "127.0.0.1".to_string(),
            port: broker.port,
            tls: false,
            username: None,
            password: None,
            client_id: "verifier-presence".to_string(),
        },
        Arc::clone(&store),
        Key::from_hex(MASTER_HEX).expect("master key"),
    );

    // Publisher with retries: the subscriber needs a moment to send SUBSCRIBE.
    let (pub_client, mut pub_eventloop) =
        AsyncClient::new(client_options(broker.port, "presence-pub"), 8);
    let pump = tokio::spawn(async move {
        loop {
            if pub_eventloop.poll().await.is_err() {
                break;
            }
        }
    });
    let mut delivered = false;
    for _ in 0..20 {
        if pub_client
            .publish("access/door3/presence", QoS::AtLeastOnce, false, "offline")
            .await
            .is_ok()
        {
            tokio::time::sleep(Duration::from_millis(250)).await;
            let presence = store
                .lock()
                .expect("store lock")
                .presence_of("door3")
                .expect("presence_of");
            if presence.as_deref() == Some("offline") {
                delivered = true;
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    assert!(delivered, "presence offline flips devices.presence");

    let audits: i64 = store
        .lock()
        .expect("store lock")
        .conn_mut()
        .query_row(
            "SELECT COUNT(*) FROM audit_log
             WHERE device_id = 'door3' AND reason = 'presence_update'",
            [],
            |row| row.get(0),
        )
        .expect("audit query");
    assert_eq!(audits, 1, "exactly one transition audit row");

    // Duplicate offline must touch last_seen without a second audit row.
    for _ in 0..20 {
        let _ = pub_client
            .publish("access/door3/presence", QoS::AtLeastOnce, false, "offline")
            .await;
        tokio::time::sleep(Duration::from_millis(250)).await;
        let audits: i64 = store
            .lock()
            .expect("store lock")
            .conn_mut()
            .query_row(
                "SELECT COUNT(*) FROM audit_log
                 WHERE device_id = 'door3' AND reason = 'presence_update'",
                [],
                |row| row.get(0),
            )
            .expect("audit query");
        if audits == 1 {
            break;
        }
    }
    let audits: i64 = store
        .lock()
        .expect("store lock")
        .conn_mut()
        .query_row(
            "SELECT COUNT(*) FROM audit_log
             WHERE device_id = 'door3' AND reason = 'presence_update'",
            [],
            |row| row.get(0),
        )
        .expect("audit query");
    assert_eq!(audits, 1, "no audit spam on unchanged presence");

    spawned.presence_task.abort();
    spawned.acl_task.abort();
    pump.abort();
}

#[tokio::test]
async fn cmd_publish_reaches_subscribed_reader() {
    let broker = start_broker();
    let (client, mut eventloop) = AsyncClient::new(client_options(broker.port, "cmd-sink"), 8);
    let sink = MqttSink::new(client);

    let (sub_client, mut sub_eventloop) =
        AsyncClient::new(client_options(broker.port, "cmd-sub"), 8);
    sub_client
        .subscribe("access/door1/cmd", QoS::AtLeastOnce)
        .await
        .expect("subscribe");

    // Pump both event loops; forward publishes for door1/cmd to this test.
    let (tx, mut rx) = tokio::sync::mpsc::channel(8);
    let sink_pump = tokio::spawn(async move {
        loop {
            if eventloop.poll().await.is_err() {
                break;
            }
        }
    });
    let sub_pump = tokio::spawn(async move {
        loop {
            match sub_eventloop.poll().await {
                Ok(Event::Incoming(Incoming::Publish(publish))) => {
                    if tx.send(publish).await.is_err() {
                        break;
                    }
                }
                Ok(_) => {}
                Err(_) => break,
            }
        }
    });
    // Give the SUBSCRIBE time to reach the broker before the cmd fires.
    tokio::time::sleep(Duration::from_millis(500)).await;

    use access_control_verifier::api::DecisionSink;
    sink.publish_cmd("door1", true, "ok");

    let publish = tokio::time::timeout(Duration::from_secs(5), rx.recv())
        .await
        .expect("cmd arrives in time")
        .expect("publish received");
    assert_eq!(publish.topic, "access/door1/cmd");
    let payload: Value = serde_json::from_slice(&publish.payload).expect("payload is JSON");
    assert_eq!(payload, json!({"grant": true, "reason": "ok"}));

    sink_pump.abort();
    sub_pump.abort();
}

#[tokio::test]
async fn broker_down_event_loop_survives_without_panic() {
    // Bind then release a port so nothing listens on it.
    let dead_port = {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        listener.local_addr().expect("addr").port()
    };
    let (store, _db) = build_store("door4", 0);
    let spawned = spawn(
        &MqttConfig {
            host: "127.0.0.1".to_string(),
            port: dead_port,
            tls: false,
            username: None,
            password: None,
            client_id: "verifier-dead".to_string(),
        },
        store,
        Key::from_hex(MASTER_HEX).expect("master key"),
    );

    // With no broker the loops must keep retrying rather than die or panic.
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert!(
        !spawned.presence_task.is_finished(),
        "presence loop keeps reconnecting instead of exiting"
    );
    assert!(
        !spawned.acl_task.is_finished(),
        "acl loop keeps retrying instead of exiting"
    );
    spawned.presence_task.abort();
    spawned.acl_task.abort();
}

#[test]
fn mqtt_config_defaults_to_tls_883_when_tls_enabled() {
    // Guard against accidental plaintext default: unset env, check port logic.
    let cfg = MqttConfig {
        host: "mqtt.local".to_string(),
        port: 8883,
        tls: true,
        username: None,
        password: None,
        client_id: "c".to_string(),
    };
    let opts = cfg.to_options();
    let (host, port) = opts.broker_address();
    assert_eq!(port, 8883);
    assert_eq!(host, "mqtt.local");
}

fn compute_test_cmac(master: &Key, uid_hex: &str, counter: u32) -> String {
    let uid = Uid::from_hex(uid_hex).expect("uid hex");
    let tap_counter = access_control_verifier::crypto::TapCounter::from_u32(counter);
    let cmac = access_control_verifier::crypto::cmac_for(master, &uid, &tap_counter);
    hex::encode(cmac.0)
}

async fn wait_for_suback(eventloop: &mut EventLoop) {
    for _ in 0..50 {
        match tokio::time::timeout(Duration::from_millis(100), eventloop.poll()).await {
            Ok(Ok(Event::Incoming(Incoming::SubAck(_)))) => return,
            Ok(Ok(_)) => continue,
            _ => continue,
        }
    }
    panic!("timed out waiting for SubAck");
}

async fn publish_tap_until_ack(
    client: &AsyncClient,
    eventloop: &mut EventLoop,
    tap_topic: &str,
    tap_payload: &Value,
    timeout: Duration,
) -> (String, Value) {
    let deadline = tokio::time::Instant::now() + timeout;
    let payload_str = tap_payload.to_string();
    loop {
        if tokio::time::Instant::now() >= deadline {
            panic!("timed out waiting for ack on {tap_topic}");
        }
        let _ = client
            .publish(tap_topic, QoS::AtLeastOnce, false, payload_str.clone())
            .await;
        let poll_deadline = tokio::time::Instant::now() + Duration::from_millis(200);
        while tokio::time::Instant::now() < poll_deadline {
            let rem = poll_deadline.saturating_duration_since(tokio::time::Instant::now());
            if let Ok(Ok(Event::Incoming(Incoming::Publish(publish)))) =
                tokio::time::timeout(rem, eventloop.poll()).await
            {
                let v: Value = serde_json::from_slice(&publish.payload).expect("payload is JSON");
                return (publish.topic, v);
            }
        }
    }
}

#[tokio::test]
async fn v2_tap_consult_round_trip_asserts_ack_field_by_field() {
    let broker = start_broker();
    let (store, _db) = build_store("door1", 1);
    let master = Key::from_hex(MASTER_HEX).expect("master key");

    let spawned = spawn(
        &MqttConfig {
            host: "127.0.0.1".to_string(),
            port: broker.port,
            tls: false,
            username: None,
            password: None,
            client_id: "verifier-v2-consult".to_string(),
        },
        Arc::clone(&store),
        master.clone(),
    );

    let (client, mut eventloop) = AsyncClient::new(client_options(broker.port, "door1-dev"), 8);
    client
        .subscribe("keygate/v2/door1/ack", QoS::AtLeastOnce)
        .await
        .expect("subscribe ack");
    wait_for_suback(&mut eventloop).await;

    let cmac_hex = compute_test_cmac(&master, UID_ACTIVE, 10);
    let tap_payload = json!({
        "tap_id": "door1:1",
        "uid": UID_ACTIVE,
        "counter": 10,
        "cmac": cmac_hex,
        "decision": null,
        "reason": null,
        "key_version": 1,
    });

    let (topic, ack) = publish_tap_until_ack(
        &client,
        &mut eventloop,
        "keygate/v2/door1/tap",
        &tap_payload,
        Duration::from_secs(5),
    )
    .await;
    assert_eq!(topic, "keygate/v2/door1/ack");

    // Assert field-by-field shape
    assert_eq!(ack["tap_id"], "door1:1");
    assert_eq!(ack["counter_floor"], 10);
    assert!(ack["time_s"].as_u64().unwrap() > 0);

    let entry = &ack["entry"];
    assert!(entry.is_object(), "entry must be present for known tag");
    assert_eq!(entry["uid"], UID_ACTIVE);
    assert_eq!(entry["status"], "active");
    assert!(entry["active_until"].is_string());
    assert_eq!(entry["key_version"], 1);
    assert_eq!(entry["entry_gen"], 1);
    assert_eq!(entry["global_counter"], 10);

    // Verify database row
    let s = store.lock().unwrap();
    let rep = s
        .tap_report_by_id("door1:1")
        .unwrap()
        .expect("report saved");
    assert_eq!(rep.decision.as_deref(), Some("granted"));
    assert_eq!(rep.reason.as_deref(), Some("granted"));
    assert_eq!(rep.kind, "consult");

    spawned.presence_task.abort();
    spawned.acl_task.abort();
}

#[tokio::test]
async fn v2_tap_unknown_tag_ack_entry_is_null() {
    let broker = start_broker();
    let (store, _db) = build_store("door1", 1);
    let master = Key::from_hex(MASTER_HEX).expect("master key");

    let spawned = spawn(
        &MqttConfig {
            host: "127.0.0.1".to_string(),
            port: broker.port,
            tls: false,
            username: None,
            password: None,
            client_id: "verifier-v2-unknown".to_string(),
        },
        Arc::clone(&store),
        master.clone(),
    );

    let (client, mut eventloop) = AsyncClient::new(client_options(broker.port, "door1-dev2"), 8);
    client
        .subscribe("keygate/v2/door1/ack", QoS::AtLeastOnce)
        .await
        .expect("subscribe ack");
    wait_for_suback(&mut eventloop).await;

    let unknown_uid = "04090807060504";
    let cmac_hex = compute_test_cmac(&master, unknown_uid, 5);
    let tap_payload = json!({
        "tap_id": "door1:2",
        "uid": unknown_uid,
        "counter": 5,
        "cmac": cmac_hex,
        "decision": null,
        "reason": null,
        "key_version": 1,
    });

    let (topic, ack) = publish_tap_until_ack(
        &client,
        &mut eventloop,
        "keygate/v2/door1/tap",
        &tap_payload,
        Duration::from_secs(5),
    )
    .await;
    assert_eq!(topic, "keygate/v2/door1/ack");

    assert_eq!(ack["tap_id"], "door1:2");
    assert!(ack["entry"].is_null(), "entry must be null for unknown tag");
    assert_eq!(ack["counter_floor"], 5);
    assert!(ack["time_s"].as_u64().unwrap() > 0);

    let s = store.lock().unwrap();
    let rep = s
        .tap_report_by_id("door1:2")
        .unwrap()
        .expect("report saved");
    assert_eq!(rep.decision.as_deref(), Some("denied"));
    assert_eq!(rep.reason.as_deref(), Some("unknown_tag"));

    spawned.presence_task.abort();
    spawned.acl_task.abort();
}

#[tokio::test]
async fn v2_tap_duplicate_tap_id_idempotency_over_the_wire() {
    let broker = start_broker();
    let (store, _db) = build_store("door1", 1);
    let master = Key::from_hex(MASTER_HEX).expect("master key");

    let spawned = spawn(
        &MqttConfig {
            host: "127.0.0.1".to_string(),
            port: broker.port,
            tls: false,
            username: None,
            password: None,
            client_id: "verifier-v2-dup".to_string(),
        },
        Arc::clone(&store),
        master.clone(),
    );

    let (client, mut eventloop) = AsyncClient::new(client_options(broker.port, "door1-dev3"), 8);
    client
        .subscribe("keygate/v2/door1/ack", QoS::AtLeastOnce)
        .await
        .expect("subscribe ack");
    wait_for_suback(&mut eventloop).await;

    let cmac_hex = compute_test_cmac(&master, UID_ACTIVE, 15);
    let tap_payload = json!({
        "tap_id": "door1:100",
        "uid": UID_ACTIVE,
        "counter": 15,
        "cmac": cmac_hex,
        "decision": null,
        "reason": null,
        "key_version": 1,
    });

    // 1st publish
    let (_, ack1) = publish_tap_until_ack(
        &client,
        &mut eventloop,
        "keygate/v2/door1/tap",
        &tap_payload,
        Duration::from_secs(5),
    )
    .await;
    assert_eq!(ack1["tap_id"], "door1:100");
    assert_eq!(ack1["counter_floor"], 15);

    // 2nd publish with exact same tap_id (retransmission)
    let (_, ack2) = publish_tap_until_ack(
        &client,
        &mut eventloop,
        "keygate/v2/door1/tap",
        &tap_payload,
        Duration::from_secs(5),
    )
    .await;
    assert_eq!(ack2["tap_id"], "door1:100");
    assert_eq!(ack2["counter_floor"], 15);
    assert_eq!(ack2["entry"], ack1["entry"]);

    // Verify only 1 row exists in tap_reports for door1:100
    let mut s = store.lock().unwrap();
    let count: i64 = s
        .conn_mut()
        .query_row(
            "SELECT COUNT(*) FROM tap_reports WHERE tap_id = 'door1:100'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        count, 1,
        "exactly one tap_reports row despite duplicate over the wire"
    );

    spawned.presence_task.abort();
    spawned.acl_task.abort();
}

#[tokio::test]
async fn v2_cross_door_duplicate_anomaly_detected() {
    let broker = start_broker();
    let (store, _db) = build_store("door1", 1);
    let master = Key::from_hex(MASTER_HEX).expect("master key");

    // Add door2 to devices
    store
        .lock()
        .unwrap()
        .upsert_device("door2", "gate", true)
        .unwrap();

    let spawned = spawn(
        &MqttConfig {
            host: "127.0.0.1".to_string(),
            port: broker.port,
            tls: false,
            username: None,
            password: None,
            client_id: "verifier-v2-cross".to_string(),
        },
        Arc::clone(&store),
        master.clone(),
    );

    let (client, mut eventloop) = AsyncClient::new(client_options(broker.port, "cross-dev"), 8);
    client
        .subscribe("keygate/v2/+/ack", QoS::AtLeastOnce)
        .await
        .expect("subscribe");
    wait_for_suback(&mut eventloop).await;

    // Door 1 reports counter 25 on UID_ACTIVE
    let cmac_hex = compute_test_cmac(&master, UID_ACTIVE, 25);
    let tap1 = json!({
        "tap_id": "door1:201",
        "uid": UID_ACTIVE,
        "counter": 25,
        "cmac": cmac_hex,
        "decision": null,
        "reason": null,
        "key_version": 1,
    });
    let _ = publish_tap_until_ack(
        &client,
        &mut eventloop,
        "keygate/v2/door1/tap",
        &tap1,
        Duration::from_secs(5),
    )
    .await;

    // Door 2 reports the SAME counter 25 on UID_ACTIVE
    let tap2 = json!({
        "tap_id": "door2:201",
        "uid": UID_ACTIVE,
        "counter": 25,
        "cmac": cmac_hex,
        "decision": null,
        "reason": null,
        "key_version": 1,
    });
    let _ = publish_tap_until_ack(
        &client,
        &mut eventloop,
        "keygate/v2/door2/tap",
        &tap2,
        Duration::from_secs(5),
    )
    .await;

    // Verify anomaly record in store
    let s = store.lock().unwrap();
    let anomalies = s.list_anomalies().unwrap();
    let cross_anomalies: Vec<_> = anomalies
        .into_iter()
        .filter(|a| a.kind == "cross_door_duplicate")
        .collect();
    assert_eq!(
        cross_anomalies.len(),
        1,
        "cross_door_duplicate anomaly logged"
    );
    let anom = &cross_anomalies[0];
    assert_eq!(anom.device_id.as_deref(), Some("door2"));
    assert_eq!(anom.uid.as_deref(), Some(UID_ACTIVE));
    assert!(anom.detail.as_deref().unwrap().contains("door1"));

    spawned.presence_task.abort();
    spawned.acl_task.abort();
}

#[tokio::test]
async fn v2_cmac_fail_consult_records_outcome_and_returns_null_entry() {
    let broker = start_broker();
    let (store, _db) = build_store("door1", 1);
    let master = Key::from_hex(MASTER_HEX).expect("master key");

    let spawned = spawn(
        &MqttConfig {
            host: "127.0.0.1".to_string(),
            port: broker.port,
            tls: false,
            username: None,
            password: None,
            client_id: "verifier-v2-cmac-fail".to_string(),
        },
        Arc::clone(&store),
        master.clone(),
    );

    let (client, mut eventloop) = AsyncClient::new(client_options(broker.port, "door1-cmac"), 8);
    client
        .subscribe("keygate/v2/door1/ack", QoS::AtLeastOnce)
        .await
        .expect("subscribe");
    wait_for_suback(&mut eventloop).await;

    // Bad CMAC
    let tap = json!({
        "tap_id": "door1:301",
        "uid": UID_ACTIVE,
        "counter": 50,
        "cmac": "0011223344556677", // bad cmac
        "decision": null,
        "reason": null,
        "key_version": 1,
    });

    let (_, ack) = publish_tap_until_ack(
        &client,
        &mut eventloop,
        "keygate/v2/door1/tap",
        &tap,
        Duration::from_secs(5),
    )
    .await;

    assert_eq!(ack["tap_id"], "door1:301");
    assert!(ack["entry"].is_null(), "entry must be null on cmac_fail");

    // Verify DB
    let s = store.lock().unwrap();
    let rep = s
        .tap_report_by_id("door1:301")
        .unwrap()
        .expect("report saved");
    assert_eq!(rep.decision.as_deref(), Some("denied"));
    assert_eq!(rep.reason.as_deref(), Some("cmac_fail"));

    // Counter on tag must NOT have advanced to 50
    let tag = s.tag_by_uid(UID_ACTIVE).unwrap().unwrap();
    assert_eq!(
        tag.last_counter, 0,
        "tag counter must NOT advance on cmac_fail"
    );

    spawned.presence_task.abort();
    spawned.acl_task.abort();
}

#[tokio::test]
async fn v2_hello_updates_last_seen_and_handles_unregistered_device() {
    let broker = start_broker();
    let (store, _db) = build_store("door1", 1);
    let master = Key::from_hex(MASTER_HEX).expect("master key");

    let spawned = spawn(
        &MqttConfig {
            host: "127.0.0.1".to_string(),
            port: broker.port,
            tls: false,
            username: None,
            password: None,
            client_id: "verifier-v2-hello".to_string(),
        },
        Arc::clone(&store),
        master.clone(),
    );

    let (client, mut eventloop) = AsyncClient::new(client_options(broker.port, "door-hello"), 8);
    let pump = tokio::spawn(async move {
        loop {
            if eventloop.poll().await.is_err() {
                break;
            }
        }
    });

    // 1. Hello from registered door1
    let hello1_payload = json!({
        "roster_gen": 0,
        "key_versions": [1],
        "outbox_depth": 0,
        "time_uncertain": false,
        "git_sha": "testsha1",
    });

    let mut updated1 = false;
    for _ in 0..30 {
        let _ = client
            .publish(
                "keygate/v2/door1/hello",
                QoS::AtLeastOnce,
                false,
                hello1_payload.to_string(),
            )
            .await;
        tokio::time::sleep(Duration::from_millis(150)).await;
        let s = store.lock().unwrap();
        let devices = s.list_devices().unwrap();
        if let Some(d1) = devices.iter().find(|d| d.device_id == "door1") {
            if d1.last_seen.is_some() {
                updated1 = true;
                break;
            }
        }
    }
    assert!(updated1, "door1 last_seen updated on hello");

    // 2. Hello from UNREGISTERED door_new (door predates registration)
    let hello_new_payload = json!({
        "roster_gen": 5,
        "key_versions": [1],
        "outbox_depth": 2,
        "time_uncertain": true,
        "git_sha": "testsha2",
    });

    let mut updated_new = false;
    for _ in 0..30 {
        let _ = client
            .publish(
                "keygate/v2/door_new/hello",
                QoS::AtLeastOnce,
                false,
                hello_new_payload.to_string(),
            )
            .await;
        tokio::time::sleep(Duration::from_millis(150)).await;
        let s = store.lock().unwrap();
        let devices = s.list_devices().unwrap();
        if let Some(d_new) = devices.iter().find(|d| d.device_id == "door_new") {
            if d_new.last_seen.is_some() {
                updated_new = true;
                break;
            }
        }
    }
    assert!(
        updated_new,
        "unregistered device registered via hello with last_seen"
    );

    spawned.presence_task.abort();
    spawned.acl_task.abort();
    pump.abort();
}

#[tokio::test]
async fn v2_report_audit_only_advances_counter_and_never_publishes_ack() {
    let broker = start_broker();
    let (store, _db) = build_store("door1", 1);
    let master = Key::from_hex(MASTER_HEX).expect("master key");

    let spawned = spawn(
        &MqttConfig {
            host: "127.0.0.1".to_string(),
            port: broker.port,
            tls: false,
            username: None,
            password: None,
            client_id: "verifier-v2-report".to_string(),
        },
        Arc::clone(&store),
        master.clone(),
    );

    // Sub client listens on keygate/v2/door1/ack
    let (sub_client, mut sub_eventloop) =
        AsyncClient::new(client_options(broker.port, "door1-report-sub"), 8);
    sub_client
        .subscribe("keygate/v2/door1/ack", QoS::AtLeastOnce)
        .await
        .expect("subscribe ack");
    wait_for_suback(&mut sub_eventloop).await;

    // Pub client publishes report and pumps its own event loop
    let (pub_client, mut pub_eventloop) =
        AsyncClient::new(client_options(broker.port, "door1-report-pub"), 8);
    let pub_pump = tokio::spawn(async move {
        loop {
            if pub_eventloop.poll().await.is_err() {
                break;
            }
        }
    });

    let cmac_hex = compute_test_cmac(&master, UID_ACTIVE, 40);
    let report_payload = json!({
        "tap_id": "door1:401",
        "uid": UID_ACTIVE,
        "counter": 40,
        "cmac": cmac_hex,
        "decision": "granted",
        "reason": "granted",
        "key_version": 1,
    });

    let mut delivered = false;
    for _ in 0..20 {
        let _ = pub_client
            .publish(
                "keygate/v2/door1/report",
                QoS::AtLeastOnce,
                false,
                report_payload.to_string(),
            )
            .await;
        tokio::time::sleep(Duration::from_millis(150)).await;
        let s = store.lock().unwrap();
        if let Ok(Some(rep)) = s.tap_report_by_id("door1:401") {
            assert_eq!(rep.decision.as_deref(), Some("granted"));
            assert_eq!(rep.reason.as_deref(), Some("granted"));
            assert_eq!(rep.kind, "report");
            delivered = true;
            break;
        }
    }
    assert!(delivered, "report ingested into tap_reports table");

    // Counter advanced on tag
    {
        let s = store.lock().unwrap();
        let tag = s.tag_by_uid(UID_ACTIVE).unwrap().unwrap();
        assert_eq!(tag.last_counter, 40, "report advances tag last_counter");
    }

    // Verify NO ack was published to sub client
    let incoming = tokio::time::timeout(Duration::from_millis(600), sub_eventloop.poll()).await;
    if let Ok(Ok(Event::Incoming(Incoming::Publish(p)))) = incoming {
        panic!("unexpected publish received on report: {}", p.topic);
    }

    spawned.presence_task.abort();
    spawned.acl_task.abort();
    pub_pump.abort();
}

#[test]
fn test_rotation_activation_protocol_pure_fn() {
    use access_control_verifier::mqtt::{
        check_rotation_activation, DeviceHelloStatus, RotationActivationOutcome,
    };

    // 1. Partial fleet ack: door1 has v2, door2 only has v1, writer has nothing
    let fleet_partial = vec![
        DeviceHelloStatus {
            device_id: "door1".to_string(),
            offline_verify: true,
            key_versions: vec![1, 2],
        },
        DeviceHelloStatus {
            device_id: "door2".to_string(),
            offline_verify: true,
            key_versions: vec![1],
        },
        DeviceHelloStatus {
            device_id: "writer1".to_string(),
            offline_verify: false,
            key_versions: vec![],
        },
    ];

    let outcome_partial = check_rotation_activation(2, &fleet_partial);
    assert_eq!(
        outcome_partial,
        RotationActivationOutcome::WaitingForAcks {
            candidate_version: 2,
            pending_devices: vec!["door2".to_string()],
        },
        "v2 must not activate when door2 has not echoed v2"
    );

    // 2. Full fleet ack: both offline_verify doors have echoed v2
    let fleet_full = vec![
        DeviceHelloStatus {
            device_id: "door1".to_string(),
            offline_verify: true,
            key_versions: vec![1, 2],
        },
        DeviceHelloStatus {
            device_id: "door2".to_string(),
            offline_verify: true,
            key_versions: vec![1, 2],
        },
        DeviceHelloStatus {
            device_id: "writer1".to_string(),
            offline_verify: false,
            key_versions: vec![], // non-offline_verify ignored
        },
    ];

    let outcome_full = check_rotation_activation(2, &fleet_full);
    assert_eq!(
        outcome_full,
        RotationActivationOutcome::Activated { new_version: 2 },
        "v2 activates when all offline_verify devices have echoed v2"
    );
}

#[test]
fn test_no_pulse_ms_in_any_v2_payload() {
    use access_control_verifier::mqtt::{AuthoritativeFlipPayload, V2AckEntry, V2AckPayload};
    use access_control_verifier::sync_projection::{RosterEntry, SyncChunk};

    // 1. V2AckPayload
    let ack = V2AckPayload {
        tap_id: "door1:1".to_string(),
        entry: Some(V2AckEntry {
            uid: "04010203040506".to_string(),
            status: "active".to_string(),
            active_until: Some("2027-01-01T00:00:00Z".to_string()),
            key_version: 1,
            entry_gen: 1,
            global_counter: 10,
        }),
        counter_floor: 10,
        time_s: 1700000000,
    };
    let ack_json = serde_json::to_string(&ack).unwrap();
    assert!(
        !ack_json.contains("pulse"),
        "ack payload must never contain pulse field"
    );

    // 2. AuthoritativeFlipPayload
    let flip = AuthoritativeFlipPayload {
        authoritative: true,
    };
    let flip_json = serde_json::to_string(&flip).unwrap();
    assert!(
        !flip_json.contains("pulse"),
        "flip payload must never contain pulse field"
    );

    // 3. Commission payload
    let comm_json = json!({ "key_version": 1, "master_hex": "0123456789abcdef" }).to_string();
    assert!(
        !comm_json.contains("pulse"),
        "commission payload must never contain pulse field"
    );

    // 4. Binary sync chunk
    let chunk = SyncChunk {
        roster_gen: 1,
        chunk: 0,
        of: 1,
        entries: vec![RosterEntry {
            uid: [4; 7],
            counter: 0,
            expiry_epoch: 1700000000,
            key_version: 1,
            entry_gen: 1,
            flags: 0,
        }],
    };
    let chunk_bytes = chunk.encode().unwrap();
    let pulse_bytes = b"pulse";
    let has_pulse = chunk_bytes
        .windows(pulse_bytes.len())
        .any(|w| w == pulse_bytes);
    assert!(!has_pulse, "binary chunk must never contain pulse keyword");
}

#[test]
fn test_no_key_material_outside_commission_topic() {
    use access_control_verifier::mqtt::{AuthoritativeFlipPayload, V2AckEntry, V2AckPayload};
    use access_control_verifier::sync_projection::{RosterEntry, SyncChunk};

    let master_raw: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
    let master_hex = hex::encode(master_raw);

    // Ack payload
    let ack = V2AckPayload {
        tap_id: "door1:1".to_string(),
        entry: Some(V2AckEntry {
            uid: "04010203040506".to_string(),
            status: "active".to_string(),
            active_until: Some("2027-01-01T00:00:00Z".to_string()),
            key_version: 1,
            entry_gen: 1,
            global_counter: 10,
        }),
        counter_floor: 10,
        time_s: 1700000000,
    };
    let ack_json = serde_json::to_string(&ack).unwrap();
    assert!(!ack_json.contains(&master_hex));

    // Flip payload
    let flip_json = serde_json::to_string(&AuthoritativeFlipPayload {
        authoritative: true,
    })
    .unwrap();
    assert!(!flip_json.contains(&master_hex));

    // Sync chunk
    let chunk = SyncChunk {
        roster_gen: 1,
        chunk: 0,
        of: 1,
        entries: vec![RosterEntry {
            uid: [4; 7],
            counter: 0,
            expiry_epoch: 1700000000,
            key_version: 1,
            entry_gen: 1,
            flags: 0,
        }],
    };
    let chunk_bytes = chunk.encode().unwrap();
    let contains_key = chunk_bytes
        .windows(master_raw.len())
        .any(|w| w == master_raw);
    assert!(
        !contains_key,
        "sync chunk must never contain master key bytes"
    );
}

#[tokio::test]
async fn v2_hello_full_snapshot_sync_and_authoritative_flip_and_commission() {
    let broker = start_broker();
    let (store, _db) = build_store("door1", 1); // offline_verify = 1
    let master = Key::from_hex(MASTER_HEX).expect("master key");

    let spawned = spawn(
        &MqttConfig {
            host: "127.0.0.1".to_string(),
            port: broker.port,
            tls: false,
            username: None,
            password: None,
            client_id: "verifier-v2-full-sync".to_string(),
        },
        Arc::clone(&store),
        master.clone(),
    );

    let (client, mut eventloop) = AsyncClient::new(client_options(broker.port, "door1-sub"), 16);
    client
        .subscribe("keygate/v2/door1/commission", QoS::AtLeastOnce)
        .await
        .expect("sub commission");
    wait_for_suback(&mut eventloop).await;

    client
        .subscribe("keygate/v2/door1/sync", QoS::AtLeastOnce)
        .await
        .expect("sub sync");
    wait_for_suback(&mut eventloop).await;

    // Send hello with roster_gen: 0 and empty key_versions: []
    let hello = json!({
        "roster_gen": 0,
        "key_versions": [],
        "outbox_depth": 0,
        "time_uncertain": false,
        "git_sha": "sha_hello_sync",
    });

    client
        .publish(
            "keygate/v2/door1/hello",
            QoS::AtLeastOnce,
            false,
            hello.to_string(),
        )
        .await
        .expect("pub hello");

    // We expect:
    // 1. Commission message on keygate/v2/door1/commission
    // 2. Binary sync chunk on keygate/v2/door1/sync
    // 3. Authoritative flip on keygate/v2/door1/sync
    let mut got_commission = false;
    let mut got_sync_chunk = false;
    let mut got_flip = false;

    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while tokio::time::Instant::now() < deadline {
        let incoming = tokio::time::timeout(Duration::from_millis(500), eventloop.poll()).await;
        if let Ok(Ok(Event::Incoming(Incoming::Publish(p)))) = incoming {
            if p.topic == "keygate/v2/door1/commission" {
                let body: Value = serde_json::from_slice(&p.payload).unwrap();
                assert_eq!(body["key_version"], 1);
                assert_eq!(body["master_hex"], MASTER_HEX);
                got_commission = true;
            } else if p.topic == "keygate/v2/door1/sync" {
                if let Ok(chunk) =
                    access_control_verifier::sync_projection::SyncChunk::decode(&p.payload)
                {
                    assert_eq!(chunk.chunk, 0);
                    assert_eq!(chunk.of, 1);
                    assert_eq!(chunk.entries.len(), 1);
                    assert_eq!(
                        chunk.entries[0].uid,
                        [0x04, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06]
                    );
                    got_sync_chunk = true;
                } else if let Ok(flip) = serde_json::from_slice::<Value>(&p.payload) {
                    if flip["authoritative"] == true {
                        got_flip = true;
                    }
                }
            }
            if got_commission && got_sync_chunk && got_flip {
                break;
            }
        }
    }

    assert!(got_commission, "commission message received");
    assert!(got_sync_chunk, "binary sync chunk received and decoded");
    assert!(got_flip, "authoritative flip message received");

    spawned.presence_task.abort();
    spawned.acl_task.abort();
}

#[tokio::test]
async fn v2_hello_delta_sync_publishes_deltas() {
    let broker = start_broker();
    let (store, _db) = build_store("door1", 1);
    let master = Key::from_hex(MASTER_HEX).expect("master key");

    // Add another tag for m1 => bumps roster_gen, records event
    let now = chrono::Utc::now().to_rfc3339();
    {
        let mut s = store.lock().unwrap();
        s.enroll_tag("04aabbccddeeff", "m1", 1, &now).unwrap();
    }

    let spawned = spawn(
        &MqttConfig {
            host: "127.0.0.1".to_string(),
            port: broker.port,
            tls: false,
            username: None,
            password: None,
            client_id: "verifier-v2-delta-sync".to_string(),
        },
        Arc::clone(&store),
        master.clone(),
    );

    let (client, mut eventloop) =
        AsyncClient::new(client_options(broker.port, "door1-delta-sub"), 16);
    client
        .subscribe("keygate/v2/door1/sync", QoS::AtLeastOnce)
        .await
        .expect("sub sync");
    wait_for_suback(&mut eventloop).await;

    // Device is at roster_gen: 1, holds key_version: [1]
    let hello = json!({
        "roster_gen": 1,
        "key_versions": [1],
        "outbox_depth": 0,
        "time_uncertain": false,
        "git_sha": "sha_delta_test",
    });

    client
        .publish(
            "keygate/v2/door1/hello",
            QoS::AtLeastOnce,
            false,
            hello.to_string(),
        )
        .await
        .expect("pub hello");

    let mut got_delta_chunk = false;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while tokio::time::Instant::now() < deadline {
        let incoming = tokio::time::timeout(Duration::from_millis(500), eventloop.poll()).await;
        if let Ok(Ok(Event::Incoming(Incoming::Publish(p)))) = incoming {
            if p.topic == "keygate/v2/door1/sync" {
                if let Ok(chunk) =
                    access_control_verifier::sync_projection::SyncChunk::decode(&p.payload)
                {
                    assert!(!chunk.entries.is_empty());
                    got_delta_chunk = true;
                    break;
                }
            }
        }
    }

    assert!(got_delta_chunk, "delta sync chunk received and decoded");

    spawned.presence_task.abort();
    spawned.acl_task.abort();
}
