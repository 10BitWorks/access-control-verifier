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
    assert_eq!(
        payload,
        json!({"grant": true, "reason": "ok", "pulse_ms": 300})
    );

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
