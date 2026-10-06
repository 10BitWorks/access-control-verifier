//! `emqx-device` — onboarding helper: per-device MQTT credentials + topic ACLs.
//!
//! Convenience only. This binary is never imported by the verifier service; the
//! manual EMQX Dashboard procedure in `docs/runbook.md` is the authoritative
//! fallback for onboarding.
//!
//! EMQX v5 REST endpoints used (EMQX 6.x compatible):
//!
//! * Create built-in-database auth user:
//!   `POST /api/v5/authentication/password_based%3Abuilt_in_database/users`
//!   body `{"user_id": "<device-id>", "password": "<32-char>"}`
//!   <https://docs.emqx.com/en/emqx/latest/access-control/authn/user_management.html>
//! * Create username-scoped authorization rules:
//!   `POST /api/v5/authorization/sources/built_in_database/rules/users`
//!   body `[{"username": "<device-id>", "rules": [{"permission": "allow",
//!   "action": "publish", "topic": "..."}]}]`
//!   <https://docs.emqx.com/en/emqx/latest/access-control/authz/mnesia.html>
//!
//! REST authentication: HTTP Basic with an API key + secret
//! (`EMQX_API_KEY` + `EMQX_API_SECRET`), a combined `key:secret` value in
//! `EMQX_API_KEY`, or a dashboard-issued bearer token as `EMQX_API_KEY`.
//! See <https://docs.emqx.com/en/emqx/latest/admin/api.html>.

use std::time::Duration;

use clap::{Parser, ValueEnum};
use serde::{Deserialize, Serialize};

const USER_ENDPOINT: &str = "/api/v5/authentication/password_based%3Abuilt_in_database/users";
const ACL_ENDPOINT: &str = "/api/v5/authorization/sources/built_in_database/rules/users";
const PASSWORD_LEN: usize = 32;
const APPLY_TIMEOUT: Duration = Duration::from_secs(10);

const LONG_HELP: &str = "\
Creates one EMQX MQTT device credential (username = device id, random 32-char
password) plus topic ACL rules, against the EMQX v5 REST API.

Default mode is --dry-run: prints a JSON plan (including the generated
password, exactly once) and contacts nothing. --apply POSTs the same plan to
the broker and requires credentials via environment variables.

Roles / topic sets:
  gate    publish: access/{id}/auth, access/{id}/presence
          subscribe: access/{id}/cmd, access/{id}/acl
  writer  gate topics plus publish+subscribe writer/{id}/job
  both    explicit gate+writer union (same topic set as writer)

Environment:
  EMQX_API_URL    REST base URL (default http://localhost:18083)
  EMQX_API_KEY    required for --apply; API key, combined key:secret, or
                  dashboard bearer token
  EMQX_API_SECRET optional; combined with EMQX_API_KEY as HTTP Basic auth

Exit codes: 0 success, 1 apply request failed, 2 credentials missing.";

#[derive(Debug, Parser)]
#[command(
    name = "emqx-device",
    about = "Create EMQX MQTT credentials and topic ACLs for one device (dry-run by default)",
    after_help = LONG_HELP
)]
struct Cli {
    /// Device identifier; used verbatim as the MQTT username and topic suffix.
    #[arg(long, value_name = "ID")]
    device_id: String,

    /// Topic-set role for the ACL rules.
    #[arg(long, value_enum, default_value = "gate")]
    role: Role,

    /// Print the JSON plan without contacting the broker (default mode).
    #[arg(long, conflicts_with = "apply")]
    dry_run: bool,

    /// POST the plan to the broker (requires EMQX_API_KEY, see --help).
    #[arg(long)]
    apply: bool,

    /// EMQX REST base URL.
    #[arg(long, env = "EMQX_API_URL", default_value = "http://localhost:18083")]
    api_url: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    /// Door reader: access topics only.
    Gate,
    /// Card writer: access topics plus writer job topics.
    Writer,
    /// Explicit gate+writer union (same topic set as writer).
    Both,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Publish,
    Subscribe,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AclRule {
    pub permission: String,
    pub action: Action,
    pub topic: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserPayload {
    pub user_id: String,
    pub password: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AclEntry {
    pub username: String,
    pub rules: Vec<AclRule>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Mode {
    DryRun,
    Apply,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Step {
    pub name: String,
    pub method: String,
    pub url: String,
    pub body: serde_json::Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Plan {
    pub mode: Mode,
    pub api_url: String,
    pub device_id: String,
    pub role: Role,
    pub mqtt_username: String,
    pub steps: Vec<Step>,
}

fn rule(action: Action, topic: String) -> AclRule {
    AclRule {
        permission: "allow".to_owned(),
        action,
        topic,
    }
}

pub fn build_acl_rules(device_id: &str, role: Role) -> Vec<AclRule> {
    let mut rules = vec![
        rule(Action::Publish, format!("access/{device_id}/auth")),
        rule(Action::Publish, format!("access/{device_id}/presence")),
        rule(Action::Subscribe, format!("access/{device_id}/cmd")),
        rule(Action::Subscribe, format!("access/{device_id}/acl")),
    ];
    if matches!(role, Role::Writer | Role::Both) {
        rules.push(rule(Action::Publish, format!("writer/{device_id}/job")));
        rules.push(rule(Action::Subscribe, format!("writer/{device_id}/job")));
    }
    rules
}

pub fn build_acl_entry(device_id: &str, role: Role) -> AclEntry {
    AclEntry {
        username: device_id.to_owned(),
        rules: build_acl_rules(device_id, role),
    }
}

pub fn build_user_payload(device_id: &str, password: &str) -> UserPayload {
    UserPayload {
        user_id: device_id.to_owned(),
        password: password.to_owned(),
    }
}

pub fn build_plan(api_url: &str, device_id: &str, role: Role, password: &str, mode: Mode) -> Plan {
    let base = api_url.trim_end_matches('/');
    let user_body =
        serde_json::to_value(build_user_payload(device_id, password)).expect("serializable");
    let acl_body =
        serde_json::to_value(vec![build_acl_entry(device_id, role)]).expect("serializable");
    Plan {
        mode,
        api_url: api_url.to_owned(),
        device_id: device_id.to_owned(),
        role,
        mqtt_username: device_id.to_owned(),
        steps: vec![
            Step {
                name: "create_user".to_owned(),
                method: "POST".to_owned(),
                url: format!("{base}{USER_ENDPOINT}"),
                body: user_body,
            },
            Step {
                name: "create_acl".to_owned(),
                method: "POST".to_owned(),
                url: format!("{base}{ACL_ENDPOINT}"),
                body: acl_body,
            },
        ],
    }
}

/// 32-char alphanumeric password from `/dev/urandom`.
///
/// std has no CSPRNG and the dependency list is frozen for this task, so the
/// OS entropy source is read directly. Rejection sampling (`b < 4 * 62`)
/// keeps the distribution uniform over the 62-character alphabet.
pub fn generate_password(len: usize) -> std::io::Result<String> {
    use std::io::Read;

    const CHARSET: &[u8; 62] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    let mut out = String::with_capacity(len);
    let mut buf = [0u8; 64];
    let mut rng = std::fs::File::open("/dev/urandom")?;
    while out.len() < len {
        rng.read_exact(&mut buf)?;
        for &b in &buf {
            if out.len() == len {
                break;
            }
            if b < 248 {
                out.push(char::from(CHARSET[usize::from(b) % 62]));
            }
        }
    }
    Ok(out)
}

enum Auth {
    Basic { key: String, secret: String },
    Bearer { token: String },
}

fn resolve_auth() -> Auth {
    let key = match std::env::var("EMQX_API_KEY") {
        Ok(k) if !k.is_empty() => k,
        _ => {
            eprintln!(
                "error: EMQX_API_KEY is not set; --apply requires EMQX_API_KEY \
                 (plus EMQX_API_SECRET, or a combined key:secret value). \
                 Omit --apply to dry-run."
            );
            std::process::exit(2);
        }
    };
    if let Ok(secret) = std::env::var("EMQX_API_SECRET") {
        if !secret.is_empty() {
            return Auth::Basic { key, secret };
        }
    }
    match key.split_once(':') {
        Some((k, s)) if !s.is_empty() => Auth::Basic {
            key: k.to_owned(),
            secret: s.to_owned(),
        },
        _ => Auth::Bearer { token: key },
    }
}

async fn apply_plan(client: &reqwest::Client, plan: &Plan, auth: &Auth) -> Result<(), String> {
    for step in &plan.steps {
        let rb = client.post(&step.url).json(&step.body);
        let rb = match auth {
            Auth::Basic { key, secret } => rb.basic_auth(key, Some(secret)),
            Auth::Bearer { token } => rb.bearer_auth(token),
        };
        let resp = rb
            .send()
            .await
            .map_err(|e| format!("{}: request failed: {e}", step.name))?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            let snippet: String = body.chars().take(300).collect();
            return Err(format!("{}: HTTP {status}: {snippet}", step.name));
        }
        println!("{}: HTTP {status}", step.name);
    }
    Ok(())
}

async fn run(cli: Cli) -> Result<(), String> {
    // clap forbids combining the flags; dry-run is the default either way.
    let apply = cli.apply && !cli.dry_run;
    let mode = if apply { Mode::Apply } else { Mode::DryRun };
    let password =
        generate_password(PASSWORD_LEN).map_err(|e| format!("entropy source failed: {e}"))?;

    if !apply {
        let plan = build_plan(&cli.api_url, &cli.device_id, cli.role, &password, mode);
        let json = serde_json::to_string_pretty(&plan).map_err(|e| e.to_string())?;
        println!("{json}");
        return Ok(());
    }

    let auth = resolve_auth();
    let plan = build_plan(&cli.api_url, &cli.device_id, cli.role, &password, mode);
    println!("mqtt_username={}", plan.mqtt_username);
    println!("mqtt_password={password}");
    let client = reqwest::Client::builder()
        .timeout(APPLY_TIMEOUT)
        .build()
        .map_err(|e| format!("http client: {e}"))?;
    apply_plan(&client, &plan, &auth).await?;
    println!("applied {} steps for {}", plan.steps.len(), plan.device_id);
    Ok(())
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    if let Err(err) = run(cli).await {
        eprintln!("error: {err}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gate_role_has_exactly_the_four_base_topics_with_directions() {
        let rules = build_acl_rules("gate-01", Role::Gate);
        assert_eq!(rules.len(), 4);
        let expected = [
            (Action::Publish, "access/gate-01/auth"),
            (Action::Publish, "access/gate-01/presence"),
            (Action::Subscribe, "access/gate-01/cmd"),
            (Action::Subscribe, "access/gate-01/acl"),
        ];
        for (action, topic) in expected {
            assert!(
                rules
                    .iter()
                    .any(|r| r.action == action && r.topic == topic && r.permission == "allow"),
                "missing {action:?} allow rule for {topic}"
            );
        }
        assert!(rules.iter().all(|r| !r.topic.starts_with("writer/")));
    }

    #[test]
    fn writer_role_adds_job_topics_in_both_directions() {
        let rules = build_acl_rules("w-01", Role::Writer);
        assert_eq!(rules.len(), 6);
        // base set is preserved
        assert!(rules.iter().any(|r| r.topic == "access/w-01/auth"));
        assert!(rules.iter().any(|r| r.topic == "access/w-01/cmd"));
        // job topic in both directions
        assert!(rules.iter().any(|r| {
            r.action == Action::Publish && r.topic == "writer/w-01/job" && r.permission == "allow"
        }));
        assert!(rules.iter().any(|r| {
            r.action == Action::Subscribe && r.topic == "writer/w-01/job" && r.permission == "allow"
        }));
    }

    #[test]
    fn both_role_is_gate_union_writer() {
        let gate = build_acl_rules("dev", Role::Gate);
        let writer = build_acl_rules("dev", Role::Writer);
        let both = build_acl_rules("dev", Role::Both);
        assert_eq!(both, writer);
        assert!(gate.iter().all(|r| both.contains(r)));
    }

    #[test]
    fn password_is_32_alphanumeric_chars() {
        let pw = generate_password(PASSWORD_LEN).expect("urandom available");
        assert_eq!(pw.len(), PASSWORD_LEN);
        assert!(pw.chars().all(|c| c.is_ascii_alphanumeric()));
        let second = generate_password(PASSWORD_LEN).expect("urandom available");
        assert_ne!(pw, second, "two generated passwords collided");
    }

    #[test]
    fn user_payload_uses_device_id_as_username() {
        let payload = build_user_payload("gate-07", "pw123");
        assert_eq!(payload.user_id, "gate-07");
        assert_eq!(payload.password, "pw123");
        let value = serde_json::to_value(&payload).expect("serializable");
        assert_eq!(value["user_id"], "gate-07");
        assert_eq!(value["password"], "pw123");
    }

    #[test]
    fn acl_entry_is_array_element_with_username_scope() {
        let entry = build_acl_entry("gate-07", Role::Gate);
        let value = serde_json::to_value(vec![entry]).expect("serializable");
        let arr = value.as_array().expect("array body");
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["username"], "gate-07");
        assert_eq!(arr[0]["rules"].as_array().expect("rules").len(), 4);
    }

    #[test]
    fn dry_run_plan_json_parses_and_round_trips() {
        let plan = build_plan(
            "http://localhost:18083/",
            "gate-9",
            Role::Gate,
            "Abcdefghijklmnopqrstuvwxyz012345",
            Mode::DryRun,
        );
        let json = serde_json::to_string(&plan).expect("serializable");
        let back: Plan = serde_json::from_str(&json).expect("parses");
        assert_eq!(plan, back);
        // password appears exactly once (inside the create_user body)
        assert_eq!(json.matches("Abcdefghijklmnopqrstuvwxyz012345").count(), 1);
        // endpoints are the pinned v5 paths
        assert!(plan.steps[0].url.ends_with(USER_ENDPOINT));
        assert!(plan.steps[1].url.ends_with(ACL_ENDPOINT));
        // generic JSON round-trip
        let v1: serde_json::Value = serde_json::from_str(&json).expect("value");
        let v2: serde_json::Value = serde_json::from_str(&v1.to_string()).expect("value round 2");
        assert_eq!(v1, v2);
    }
}
