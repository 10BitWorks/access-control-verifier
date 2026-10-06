use super::store::Store;
use anyhow::{Context, Result};
use chrono::Utc;
use reqwest::Client;
use rusqlite::params;
use serde::Deserialize;
use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::time::Duration;

const REQUEST_TIMEOUT_SECS: u64 = 10;
const DEFAULT_ACL_EXPIRY_DAYS: i64 = 35;
const MAX_PAGES: usize = 1000;
const DETAIL_MAX_CHARS: usize = 200;

#[derive(Debug, Clone)]
pub struct SyncConfig {
    pub authentik_url: String,
    pub authentik_token: String,
    pub authentik_group: String,
    pub sync_interval_minutes: u64,
}

impl SyncConfig {
    pub fn from_env() -> Result<Self> {
        let authentik_url = std::env::var("AUTHENTIK_URL").context("AUTHENTIK_URL must be set")?;
        let authentik_token =
            std::env::var("AUTHENTIK_TOKEN").context("AUTHENTIK_TOKEN must be set")?;
        let authentik_group =
            std::env::var("AUTHENTIK_GROUP").unwrap_or_else(|_| "status_current".to_string());
        let sync_interval_minutes = std::env::var("SYNC_INTERVAL_MINUTES")
            .unwrap_or_else(|_| "60".to_string())
            .parse::<u64>()
            .context("SYNC_INTERVAL_MINUTES must be a number")?;
        Ok(Self {
            authentik_url,
            authentik_token,
            authentik_group,
            sync_interval_minutes,
        })
    }
}

#[derive(Debug)]
pub struct SyncStats {
    pub added_or_updated: usize,
    pub removed: usize,
}

#[derive(Deserialize, Debug)]
pub struct AuthentikUser {
    pub username: String,
    pub name: Option<String>,
}

#[derive(Deserialize, Debug, Default)]
pub struct Pagination {
    pub next: Option<String>,
    #[serde(default)]
    pub total_pages: usize,
}

#[derive(Deserialize, Debug)]
pub struct AuthentikResponse {
    #[serde(default)]
    pub pagination: Pagination,
    #[serde(default)]
    pub results: Vec<AuthentikUser>,
}

pub async fn run_sync_cycle(store: Arc<Mutex<Store>>, config: &SyncConfig) -> Result<SyncStats> {
    let users = match fetch_all_users(config).await {
        Ok(users) => users,
        Err(err) => {
            tracing::warn!(error = %err, "authentik sync fetch failed");
            record_failure(store, &err).await;
            return Err(err);
        }
    };
    match apply_users(store.clone(), users).await {
        Ok(stats) => Ok(stats),
        Err(err) => {
            tracing::warn!(error = %err, "authentik sync apply failed");
            record_failure(store, &err).await;
            Err(err)
        }
    }
}

async fn fetch_all_users(config: &SyncConfig) -> Result<Vec<AuthentikUser>> {
    let client = Client::builder()
        .timeout(Duration::from_secs(REQUEST_TIMEOUT_SECS))
        .build()
        .context("Failed to build HTTP client")?;

    let url = format!(
        "{}/api/v3/core/groups/{}/users/",
        config.authentik_url, config.authentik_group
    );
    let mut users: Vec<AuthentikUser> = Vec::new();
    let mut page: usize = 1;

    loop {
        let page_str = page.to_string();
        let resp = client
            .get(&url)
            .query(&[("page_size", "100"), ("page", page_str.as_str())])
            .header(
                "Authorization",
                format!("Bearer {}", config.authentik_token),
            )
            .send()
            .await
            .context("Authentik request failed")?;

        let status = resp.status();
        if !status.is_success() {
            anyhow::bail!("Authentik API returned status {status}");
        }

        let body: AuthentikResponse = resp
            .json()
            .await
            .context("Authentik response parse failed")?;
        users.extend(body.results);

        let has_next = body
            .pagination
            .next
            .as_deref()
            .is_some_and(|next| !next.is_empty());
        let has_more_pages = body.pagination.total_pages > 0 && page < body.pagination.total_pages;
        if !has_next && !has_more_pages {
            break;
        }
        page += 1;
        if page > MAX_PAGES {
            anyhow::bail!("Authentik pagination exceeded {MAX_PAGES} pages");
        }
    }

    Ok(users)
}

async fn apply_users(store: Arc<Mutex<Store>>, users: Vec<AuthentikUser>) -> Result<SyncStats> {
    tokio::task::spawn_blocking(move || -> Result<SyncStats> {
        let mut guard = store
            .lock()
            .map_err(|_| anyhow::anyhow!("store mutex poisoned"))?;
        let acl_expiry_days: i64 = match guard.get_config("acl_expiry_days") {
            Ok(Some(value)) => value.parse().unwrap_or(DEFAULT_ACL_EXPIRY_DAYS),
            _ => DEFAULT_ACL_EXPIRY_DAYS,
        };
        let now = Utc::now();
        let now_str = now.format("%Y-%m-%dT%H:%M:%SZ").to_string();
        let active_until = (now + chrono::Duration::days(acl_expiry_days))
            .format("%Y-%m-%dT%H:%M:%SZ")
            .to_string();

        let tx = guard
            .conn_mut()
            .transaction()
            .context("Failed to begin sync transaction")?;

        let mut added_or_updated = 0usize;
        let mut seen: HashSet<String> = HashSet::new();
        for user in &users {
            let display_name = match user.name.as_deref() {
                Some(name) if !name.is_empty() => name.to_string(),
                _ => user.username.clone(),
            };
            tx.execute(
                "INSERT INTO members (member_key, display_name, active_until, source)
                 VALUES (?1, ?2, ?3, 'authentik')
                 ON CONFLICT(member_key) DO UPDATE SET
                   display_name = excluded.display_name,
                   active_until = excluded.active_until,
                   source = 'authentik'",
                params![user.username, display_name, active_until],
            )
            .context("Failed to upsert member")?;
            seen.insert(user.username.clone());
            added_or_updated += 1;
        }

        let mut to_delete: Vec<String> = Vec::new();
        {
            let mut stmt = tx
                .prepare("SELECT member_key FROM members WHERE source = 'authentik'")
                .context("Failed to prepare member query")?;
            let mut rows = stmt
                .query([])
                .context("Failed to query authentik members")?;
            while let Some(row) = rows.next().context("Failed to iterate members")? {
                let key: String = row.get(0).context("Failed to read member_key")?;
                if !seen.contains(&key) {
                    to_delete.push(key);
                }
            }
        }
        let mut removed = 0usize;
        for key in &to_delete {
            tx.execute(
                "DELETE FROM members WHERE member_key = ?1 AND source = 'authentik'",
                params![key],
            )
            .context("Failed to delete stale member")?;
            removed += 1;
        }

        tx.execute(
            "INSERT INTO sync_state (id, last_success, last_attempt, detail)
             VALUES (1, ?1, ?2, 'ok')
             ON CONFLICT(id) DO UPDATE SET
               last_success = excluded.last_success,
               last_attempt = excluded.last_attempt,
               detail = excluded.detail",
            params![now_str, now_str],
        )
        .context("Failed to update sync_state")?;
        tx.commit().context("Failed to commit sync transaction")?;

        Ok(SyncStats {
            added_or_updated,
            removed,
        })
    })
    .await
    .context("Sync write task failed")?
}

async fn record_failure(store: Arc<Mutex<Store>>, err: &anyhow::Error) {
    let mut detail = err.to_string();
    if detail.chars().count() > DETAIL_MAX_CHARS {
        detail = detail.chars().take(DETAIL_MAX_CHARS).collect();
    }
    let _ = tokio::task::spawn_blocking(move || {
        let mut guard = match store.lock() {
            Ok(guard) => guard,
            Err(_) => return,
        };
        let now_str = Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
        let _ = guard.conn_mut().execute(
            "INSERT INTO sync_state (id, last_success, last_attempt, detail)
             VALUES (1, NULL, ?1, ?2)
             ON CONFLICT(id) DO UPDATE SET
               last_attempt = excluded.last_attempt,
               detail = excluded.detail",
            params![now_str, detail],
        );
    })
    .await;
}

pub fn spawn_worker(store: Arc<Mutex<Store>>, config: SyncConfig) {
    tokio::spawn(async move {
        let mut interval =
            tokio::time::interval(Duration::from_secs(config.sync_interval_minutes * 60));
        loop {
            interval.tick().await;
            if let Err(err) = run_sync_cycle(store.clone(), &config).await {
                tracing::warn!(error = %err, "authentik sync cycle failed");
            }
        }
    });
}
