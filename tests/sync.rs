#[path = "../src/store.rs"]
pub mod store;
#[path = "../src/sync.rs"]
pub mod sync;

use anyhow::Result;
use std::sync::{Arc, Mutex};
use store::Store;
use sync::{run_sync_cycle, SyncConfig, SyncStats};
use tempfile::NamedTempFile;
use tokio::time::Duration;
use wiremock::matchers::{header, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn test_config(server_url: String) -> SyncConfig {
    SyncConfig {
        authentik_url: server_url,
        authentik_token: "test-token-123".to_string(),
        authentik_group: "status_current".to_string(),
        sync_interval_minutes: 60,
    }
}

fn open_store(file: &NamedTempFile) -> Arc<Mutex<Store>> {
    let store = Store::open(file.path()).expect("store should open");
    Arc::new(Mutex::new(store))
}

fn db_conn(file: &NamedTempFile) -> rusqlite::Connection {
    let conn = rusqlite::Connection::open(file.path()).expect("second connection should open");
    conn.busy_timeout(std::time::Duration::from_secs(5))
        .expect("busy_timeout should set");
    conn
}

fn seed_member_until(file: &NamedTempFile, key: &str, source: &str, active_until: &str) {
    let conn = db_conn(file);
    conn.execute(
        "INSERT INTO members (member_key, display_name, active_until, source)
         VALUES (?1, ?1, ?2, ?3)",
        rusqlite::params![key, active_until, source],
    )
    .expect("seed member should insert");
}

fn seed_member(file: &NamedTempFile, key: &str, source: &str) {
    seed_member_until(file, key, source, "2099-01-01T00:00:00Z");
}

fn member_keys(file: &NamedTempFile) -> Vec<String> {
    let conn = db_conn(file);
    let mut stmt = conn
        .prepare("SELECT member_key FROM members ORDER BY member_key")
        .expect("prepare should succeed");
    let keys = stmt
        .query_map([], |row| row.get::<_, String>(0))
        .expect("query should succeed")
        .collect::<Result<Vec<_>, _>>()
        .expect("rows should read");
    keys
}

fn member_field(file: &NamedTempFile, key: &str, column: &str) -> String {
    let conn = db_conn(file);
    conn.query_row(
        &format!("SELECT {column} FROM members WHERE member_key = ?1"),
        rusqlite::params![key],
        |row| row.get(0),
    )
    .expect("member row should exist")
}

fn sync_state(file: &NamedTempFile) -> (Option<String>, Option<String>, Option<String>) {
    let conn = db_conn(file);
    conn.query_row(
        "SELECT last_success, last_attempt, detail FROM sync_state WHERE id = 1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )
    .expect("sync_state row should exist")
}

#[tokio::test]
async fn test_sync_success_two_pages_three_users() {
    let mock_server = MockServer::start().await;
    let config = test_config(mock_server.uri());
    let db_file = NamedTempFile::new().unwrap();
    let store = open_store(&db_file);

    Mock::given(method("GET"))
        .and(path("/api/v3/core/groups/status_current/users/"))
        .and(query_param("page", "1"))
        .and(query_param("page_size", "100"))
        .and(header("Authorization", "Bearer test-token-123"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "pagination": {
                "next": format!("{}/api/v3/core/groups/status_current/users/?page=2", mock_server.uri()),
                "previous": null,
                "count": 3,
                "current": 1,
                "total_pages": 2
            },
            "results": [
                { "username": "alice", "name": "Alice A" },
                { "username": "bob", "name": "Bob B" }
            ]
        })))
        .mount(&mock_server)
        .await;

    Mock::given(method("GET"))
        .and(path("/api/v3/core/groups/status_current/users/"))
        .and(query_param("page", "2"))
        .and(query_param("page_size", "100"))
        .and(header("Authorization", "Bearer test-token-123"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "pagination": {
                "next": null,
                "previous": format!("{}/api/v3/core/groups/status_current/users/?page=1", mock_server.uri()),
                "count": 3,
                "current": 2,
                "total_pages": 2
            },
            "results": [
                { "username": "charlie", "name": "" }
            ]
        })))
        .mount(&mock_server)
        .await;

    let stats: SyncStats = run_sync_cycle(store.clone(), &config)
        .await
        .expect("sync should succeed");
    assert_eq!(stats.added_or_updated, 3);
    assert_eq!(stats.removed, 0);

    assert_eq!(member_keys(&db_file), vec!["alice", "bob", "charlie"]);
    assert_eq!(member_field(&db_file, "alice", "display_name"), "Alice A");
    assert_eq!(member_field(&db_file, "alice", "source"), "authentik");
    assert_eq!(member_field(&db_file, "charlie", "display_name"), "charlie");

    let now_str = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
    let active_until = member_field(&db_file, "alice", "active_until");
    assert!(
        active_until > now_str,
        "active_until {active_until} should be in the future (default 35 days)"
    );

    let (last_success, last_attempt, detail) = sync_state(&db_file);
    assert!(last_success.is_some(), "last_success should be set");
    assert!(last_attempt.is_some(), "last_attempt should be set");
    assert_eq!(detail.as_deref(), Some("ok"));
}

#[tokio::test]
async fn test_sync_page2_error_applies_nothing() {
    let mock_server = MockServer::start().await;
    let config = test_config(mock_server.uri());
    let db_file = NamedTempFile::new().unwrap();
    let store = open_store(&db_file);
    seed_member(&db_file, "keeper", "authentik");

    Mock::given(method("GET"))
        .and(path("/api/v3/core/groups/status_current/users/"))
        .and(query_param("page", "1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "pagination": { "next": "page2", "total_pages": 2, "current": 1 },
            "results": [ { "username": "alice", "name": "Alice A" } ]
        })))
        .mount(&mock_server)
        .await;

    Mock::given(method("GET"))
        .and(path("/api/v3/core/groups/status_current/users/"))
        .and(query_param("page", "2"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&mock_server)
        .await;

    let result: Result<SyncStats> = run_sync_cycle(store.clone(), &config).await;
    assert!(result.is_err(), "sync should fail on HTTP 500");

    assert_eq!(
        member_keys(&db_file),
        vec!["keeper"],
        "no page-1 users may be written on failure"
    );
    assert_eq!(
        member_field(&db_file, "keeper", "active_until"),
        "2099-01-01T00:00:00Z",
        "existing member rows must be untouched"
    );

    let (last_success, last_attempt, detail) = sync_state(&db_file);
    assert!(last_success.is_none(), "last_success must not be set");
    assert!(last_attempt.is_some(), "last_attempt should be updated");
    assert!(
        detail.is_some_and(|d| d != "ok"),
        "detail should record the error"
    );
}

#[tokio::test]
async fn test_sync_connection_error_cache_intact() {
    let db_file = NamedTempFile::new().unwrap();
    let config = test_config("http://127.0.0.1:1".to_string());
    let store = open_store(&db_file);
    seed_member(&db_file, "cached1", "authentik");
    seed_member(&db_file, "cached2", "authentik");

    let result: Result<SyncStats> = run_sync_cycle(store.clone(), &config).await;
    assert!(result.is_err(), "sync should fail on connection error");

    assert_eq!(member_keys(&db_file), vec!["cached1", "cached2"]);
    assert_eq!(
        member_field(&db_file, "cached1", "active_until"),
        "2099-01-01T00:00:00Z"
    );

    let (last_success, last_attempt, detail) = sync_state(&db_file);
    assert!(last_success.is_none(), "last_success must not be set");
    assert!(last_attempt.is_some(), "last_attempt should be updated");
    assert!(
        detail.is_some_and(|d| d != "ok"),
        "detail should record the error"
    );
}

#[tokio::test]
async fn test_sync_removes_stale_authentik_members_only() {
    let mock_server = MockServer::start().await;
    let config = test_config(mock_server.uri());
    let db_file = NamedTempFile::new().unwrap();
    let store = open_store(&db_file);
    seed_member_until(&db_file, "alice", "authentik", "2020-01-01T00:00:00Z");
    seed_member(&db_file, "bob", "authentik");
    seed_member(&db_file, "manual_user", "manual");

    Mock::given(method("GET"))
        .and(path("/api/v3/core/groups/status_current/users/"))
        .and(query_param("page", "1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "pagination": { "next": null, "total_pages": 1, "current": 1 },
            "results": [
                { "username": "alice", "name": "Alice" }
            ]
        })))
        .mount(&mock_server)
        .await;

    let stats: SyncStats = run_sync_cycle(store.clone(), &config)
        .await
        .expect("sync should succeed");
    assert_eq!(stats.added_or_updated, 1);
    assert_eq!(stats.removed, 1);

    assert_eq!(member_keys(&db_file), vec!["alice", "manual_user"]);
    assert_eq!(member_field(&db_file, "alice", "source"), "authentik");

    let now_str = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
    let refreshed_until = member_field(&db_file, "alice", "active_until");
    assert!(
        refreshed_until > now_str,
        "stale active_until {refreshed_until} must flip forward to now+acl_expiry_days"
    );
    assert_eq!(
        member_field(&db_file, "manual_user", "active_until"),
        "2099-01-01T00:00:00Z",
        "non-authentik members must not be touched"
    );

    let (last_success, _, detail) = sync_state(&db_file);
    assert!(last_success.is_some(), "last_success should be set");
    assert_eq!(detail.as_deref(), Some("ok"));
}

#[tokio::test]
async fn test_sync_timeout_cache_unchanged() {
    let mock_server = MockServer::start().await;
    let config = test_config(mock_server.uri());
    let db_file = NamedTempFile::new().unwrap();
    let store = open_store(&db_file);
    seed_member(&db_file, "cached1", "authentik");

    Mock::given(method("GET"))
        .and(path("/api/v3/core/groups/status_current/users/"))
        .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(12)))
        .mount(&mock_server)
        .await;

    let result: Result<SyncStats> = run_sync_cycle(store.clone(), &config).await;
    assert!(result.is_err(), "sync should fail on timeout");

    assert_eq!(
        member_keys(&db_file),
        vec!["cached1"],
        "cache must stay untouched on timeout"
    );
    assert_eq!(
        member_field(&db_file, "cached1", "active_until"),
        "2099-01-01T00:00:00Z"
    );

    let (last_success, last_attempt, detail) = sync_state(&db_file);
    assert!(last_success.is_none(), "last_success must not be set");
    assert!(
        last_attempt.is_some(),
        "last_attempt should be updated on timeout"
    );
    assert!(
        detail.is_some_and(|d| d != "ok"),
        "detail should record the error"
    );
}
