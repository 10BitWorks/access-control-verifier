//! `emqx-device` — onboarding helper: per-device and verifier MQTT credentials + topic ACLs.
//!
//! Convenience only. This binary is never imported by the verifier service; the
//! manual EMQX Dashboard procedure in `docs/runbook.md` is the authoritative
//! fallback for onboarding.
//!
//! EMQX v5 REST endpoints used (EMQX 6.x compatible):
//!
//! * Create built-in-database auth user:
//!   `POST /api/v5/authentication/password_based%3Abuilt_in_database/users`
//!   body `{"user_id": "<principal-id>", "password": "<32-char>"}`
//!   <https://docs.emqx.com/en/emqx/latest/access-control/authn/user_management.html>
//! * Create username-scoped authorization rules:
//!   `POST /api/v5/authorization/sources/built_in_database/rules/users`
//!   body `[{"username": "<principal-id>", "rules": [{"permission": "allow",
//!   "action": "publish", "topic": "..."}]}]`
//!   <https://docs.emqx.com/en/emqx/latest/access-control/authz/mnesia.html>
//!
//! REST authentication: HTTP Basic with an API key + secret
//! (`EMQX_API_KEY` + `EMQX_API_SECRET`), a combined `key:secret` value in
//! `EMQX_API_KEY`, or a dashboard-issued bearer token as `EMQX_API_KEY`.
//! See <https://docs.emqx.com/en/emqx/latest/admin/api.html>.

use std::time::Duration;

use clap::{Args, Parser, Subcommand, ValueEnum};
use serde::{Deserialize, Serialize};

const USER_ENDPOINT: &str = "/api/v5/authentication/password_based%3Abuilt_in_database/users";
const ACL_ENDPOINT: &str = "/api/v5/authorization/sources/built_in_database/rules/users";
const PASSWORD_LEN: usize = 32;
const APPLY_TIMEOUT: Duration = Duration::from_secs(10);

const LONG_HELP: &str = "\
Creates EMQX MQTT credentials (username = principal id, random 32-char
password) plus topic ACL rules, against the EMQX v5 REST API.

Default mode is --dry-run: prints a JSON plan (including the generated
password, exactly once) and contacts nothing. --apply POSTs the same plan to
the broker and requires credentials via environment variables.

Targets / topic sets:
  device:
    gate    publish:   access/{id}/auth, access/{id}/presence,
                       keygate/v2/{id}/hello, keygate/v2/{id}/tap,
                       keygate/v2/{id}/report, keygate/v2/{id}/diag
            subscribe: access/{id}/cmd, access/{id}/acl,
                       keygate/v2/{id}/ack, keygate/v2/{id}/sync,
                       keygate/v2/{id}/commission, keygate/v2/{id}/diag/drain
    writer  gate topics plus publish+subscribe writer/{id}/job
    both    explicit gate+writer union (same topic set as writer)

    Commission hardening note (D3): keygate/v2/{id}/commission is SUBSCRIBE-ONLY
    for the device and PUBLISH-ONLY for the verifier principal.

  verifier:
    publish:   keygate/v2/+/ack, keygate/v2/+/sync, keygate/v2/+/commission,
               writer/+/job, access/+/cmd, access/+/acl
    subscribe: keygate/v2/+/hello, keygate/v2/+/tap, keygate/v2/+/report,
               access/+/presence, writer/+/claim, writer/+/done

Environment:
  EMQX_API_URL    REST base URL (default http://localhost:18083)
  EMQX_API_KEY    required for --apply; API key, combined key:secret, or
                  dashboard bearer token
  EMQX_API_SECRET optional; combined with EMQX_API_KEY as HTTP Basic auth

Exit codes: 0 success, 1 apply request failed, 2 credentials missing.";

#[derive(Debug, Parser)]
#[command(
    name = "emqx-device",
    about = "Create EMQX MQTT credentials and topic ACLs for devices or verifier (dry-run by default)",
    after_help = LONG_HELP
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Command>,

    /// Device identifier; used verbatim as the MQTT username and topic suffix (flattened device mode).
    #[arg(long, value_name = "ID")]
    pub device_id: Option<String>,

    /// Topic-set role for the ACL rules (flattened device mode).
    #[arg(long, value_enum, default_value = "gate")]
    pub role: Role,

    /// Generate ACL rules for the verifier service principal instead of a device.
    #[arg(long, conflicts_with = "device_id", conflicts_with = "role")]
    pub verifier: bool,

    /// Username / principal ID for the verifier (default 'verifier').
    #[arg(long, default_value = "verifier", value_name = "USERNAME")]
    pub verifier_id: String,

    /// Print the JSON plan without contacting the broker (default mode).
    #[arg(long, conflicts_with = "apply")]
    pub dry_run: bool,

    /// POST the plan to the broker (requires EMQX_API_KEY, see --help).
    #[arg(long)]
    pub apply: bool,

    /// EMQX REST base URL.
    #[arg(long, env = "EMQX_API_URL", default_value = "http://localhost:18083")]
    pub api_url: String,
}

#[derive(Debug, Subcommand, Clone, PartialEq, Eq)]
pub enum Command {
    /// Create credentials and rules for a device principal (default).
    Device(DeviceArgs),
    /// Create credentials and rules for the verifier service principal.
    Verifier(VerifierArgs),
}

#[derive(Debug, Args, Clone, PartialEq, Eq)]
pub struct DeviceArgs {
    /// Device identifier; used verbatim as the MQTT username and topic suffix.
    #[arg(long, value_name = "ID")]
    pub device_id: String,

    /// Topic-set role for the ACL rules.
    #[arg(long, value_enum, default_value = "gate")]
    pub role: Role,

    /// Print the JSON plan without contacting the broker (default mode).
    #[arg(long, conflicts_with = "apply")]
    pub dry_run: bool,

    /// POST the plan to the broker (requires EMQX_API_KEY, see --help).
    #[arg(long)]
    pub apply: bool,

    /// EMQX REST base URL.
    #[arg(long, env = "EMQX_API_URL", default_value = "http://localhost:18083")]
    pub api_url: String,
}

#[derive(Debug, Args, Clone, PartialEq, Eq)]
pub struct VerifierArgs {
    /// Username / principal ID for the verifier.
    #[arg(long, default_value = "verifier", value_name = "USERNAME")]
    pub verifier_id: String,

    /// Print the JSON plan without contacting the broker (default mode).
    #[arg(long, conflicts_with = "apply")]
    pub dry_run: bool,

    /// POST the plan to the broker (requires EMQX_API_KEY, see --help).
    #[arg(long)]
    pub apply: bool,

    /// EMQX REST base URL.
    #[arg(long, env = "EMQX_API_URL", default_value = "http://localhost:18083")]
    pub api_url: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    /// Door reader: access topics and v2 reader topics.
    Gate,
    /// Card writer: access topics, v2 reader topics, plus writer job topics.
    Writer,
    /// Explicit gate+writer union (same topic set as writer).
    Both,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PrincipalKind {
    Device,
    Verifier,
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
    pub principal_kind: PrincipalKind,
    pub principal_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<Role>,
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

/// Build the complete topic ACL rules for a device principal.
///
/// Includes:
/// - Legacy access rules: `access/{id}/auth`, `access/{id}/presence` (pub); `access/{id}/cmd`, `access/{id}/acl` (sub)
/// - Optional legacy writer rules: `writer/{id}/job` (pub + sub)
/// - v2 device rules:
///     - Publish: `keygate/v2/{id}/hello`, `keygate/v2/{id}/tap`, `keygate/v2/{id}/report`, `keygate/v2/{id}/diag`
///     - Subscribe: `keygate/v2/{id}/ack`, `keygate/v2/{id}/sync`, `keygate/v2/{id}/commission`, `keygate/v2/{id}/diag/drain`
///
/// COMMISSION HARDENING (Plan D3):
/// `keygate/v2/{id}/commission` is strictly SUBSCRIBE-ONLY for device principals.
/// Device principals MUST NEVER be granted publish permission on commission topics.
pub fn build_acl_rules(device_id: &str, role: Role) -> Vec<AclRule> {
    let mut rules = vec![
        // Legacy gate family
        rule(Action::Publish, format!("access/{device_id}/auth")),
        rule(Action::Publish, format!("access/{device_id}/presence")),
        rule(Action::Subscribe, format!("access/{device_id}/cmd")),
        rule(Action::Subscribe, format!("access/{device_id}/acl")),
        // v2 device publish topics
        rule(Action::Publish, format!("keygate/v2/{device_id}/hello")),
        rule(Action::Publish, format!("keygate/v2/{device_id}/tap")),
        rule(Action::Publish, format!("keygate/v2/{device_id}/report")),
        rule(Action::Publish, format!("keygate/v2/{device_id}/diag")),
        // v2 device subscribe topics
        // Note: commission is subscribe-only for devices (Plan D3 hardening)
        rule(Action::Subscribe, format!("keygate/v2/{device_id}/ack")),
        rule(Action::Subscribe, format!("keygate/v2/{device_id}/sync")),
        rule(
            Action::Subscribe,
            format!("keygate/v2/{device_id}/commission"),
        ),
        rule(
            Action::Subscribe,
            format!("keygate/v2/{device_id}/diag/drain"),
        ),
    ];
    if matches!(role, Role::Writer | Role::Both) {
        rules.push(rule(Action::Publish, format!("writer/{device_id}/job")));
        rules.push(rule(Action::Subscribe, format!("writer/{device_id}/job")));
    }
    rules
}

/// Build the complete topic ACL rules for the verifier service principal.
///
/// Includes:
/// - Subscriptions (mirroring `mqtt.rs` event loop):
///     - `keygate/v2/+/hello`
///     - `keygate/v2/+/tap`
///     - `keygate/v2/+/report`
///     - `access/+/presence`
///     - `writer/+/claim`
///     - `writer/+/done`
/// - Publications:
///     - `keygate/v2/+/ack`
///     - `keygate/v2/+/sync`
///     - `keygate/v2/+/commission` (Plan D3: verifier is the exclusive publisher of master keys)
///     - `writer/+/job`
///     - `access/+/cmd` (legacy auth decisions until S6 retirement)
///     - `access/+/acl` (legacy retained ACLs until S6 retirement)
pub fn build_verifier_acl_rules() -> Vec<AclRule> {
    vec![
        // Verifier subscriptions
        rule(Action::Subscribe, "keygate/v2/+/hello".to_owned()),
        rule(Action::Subscribe, "keygate/v2/+/tap".to_owned()),
        rule(Action::Subscribe, "keygate/v2/+/report".to_owned()),
        rule(Action::Subscribe, "access/+/presence".to_owned()),
        rule(Action::Subscribe, "writer/+/claim".to_owned()),
        rule(Action::Subscribe, "writer/+/done".to_owned()),
        // Verifier publications
        rule(Action::Publish, "keygate/v2/+/ack".to_owned()),
        rule(Action::Publish, "keygate/v2/+/sync".to_owned()),
        // Commission hardening (Plan D3): publish-only for verifier
        rule(Action::Publish, "keygate/v2/+/commission".to_owned()),
        rule(Action::Publish, "writer/+/job".to_owned()),
        rule(Action::Publish, "access/+/cmd".to_owned()),
        rule(Action::Publish, "access/+/acl".to_owned()),
    ]
}

pub fn build_acl_entry(device_id: &str, role: Role) -> AclEntry {
    AclEntry {
        username: device_id.to_owned(),
        rules: build_acl_rules(device_id, role),
    }
}

pub fn build_verifier_acl_entry(verifier_id: &str) -> AclEntry {
    AclEntry {
        username: verifier_id.to_owned(),
        rules: build_verifier_acl_rules(),
    }
}

pub fn build_user_payload(principal_id: &str, password: &str) -> UserPayload {
    UserPayload {
        user_id: principal_id.to_owned(),
        password: password.to_owned(),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetConfig {
    Device {
        device_id: String,
        role: Role,
        apply: bool,
        api_url: String,
    },
    Verifier {
        verifier_id: String,
        apply: bool,
        api_url: String,
    },
}

impl TargetConfig {
    pub fn from_cli(cli: &Cli) -> Result<Self, String> {
        if let Some(cmd) = &cli.command {
            return match cmd {
                Command::Device(args) => Ok(TargetConfig::Device {
                    device_id: args.device_id.clone(),
                    role: args.role,
                    apply: args.apply && !args.dry_run,
                    api_url: args.api_url.clone(),
                }),
                Command::Verifier(args) => Ok(TargetConfig::Verifier {
                    verifier_id: args.verifier_id.clone(),
                    apply: args.apply && !args.dry_run,
                    api_url: args.api_url.clone(),
                }),
            };
        }

        if cli.verifier {
            return Ok(TargetConfig::Verifier {
                verifier_id: cli.verifier_id.clone(),
                apply: cli.apply && !cli.dry_run,
                api_url: cli.api_url.clone(),
            });
        }

        if let Some(device_id) = &cli.device_id {
            return Ok(TargetConfig::Device {
                device_id: device_id.clone(),
                role: cli.role,
                apply: cli.apply && !cli.dry_run,
                api_url: cli.api_url.clone(),
            });
        }

        Err("either --device-id <ID> (or subcommand 'device') or --verifier (or subcommand 'verifier') is required".to_owned())
    }
}

/// Build the REST plan for a target config.
pub fn build_target_plan(target: &TargetConfig, password: &str) -> Plan {
    match target {
        TargetConfig::Device {
            device_id,
            role,
            apply,
            api_url,
        } => {
            let base = api_url.trim_end_matches('/');
            let mode = if *apply { Mode::Apply } else { Mode::DryRun };
            let user_body = serde_json::to_value(build_user_payload(device_id, password))
                .expect("serializable");
            let acl_body = serde_json::to_value(vec![build_acl_entry(device_id, *role)])
                .expect("serializable");
            Plan {
                mode,
                api_url: api_url.clone(),
                principal_kind: PrincipalKind::Device,
                principal_id: device_id.clone(),
                role: Some(*role),
                mqtt_username: device_id.clone(),
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
        TargetConfig::Verifier {
            verifier_id,
            apply,
            api_url,
        } => {
            let base = api_url.trim_end_matches('/');
            let mode = if *apply { Mode::Apply } else { Mode::DryRun };
            let user_body = serde_json::to_value(build_user_payload(verifier_id, password))
                .expect("serializable");
            let acl_body = serde_json::to_value(vec![build_verifier_acl_entry(verifier_id)])
                .expect("serializable");
            Plan {
                mode,
                api_url: api_url.clone(),
                principal_kind: PrincipalKind::Verifier,
                principal_id: verifier_id.clone(),
                role: None,
                mqtt_username: verifier_id.clone(),
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
    }
}

/// Build the REST plan for parsed CLI options (backward compatible helper).
pub fn build_plan(cli: &Cli, password: &str) -> Plan {
    let target = TargetConfig::from_cli(cli).expect("valid CLI target configuration");
    build_target_plan(&target, password)
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
    let target = TargetConfig::from_cli(&cli)?;
    let password =
        generate_password(PASSWORD_LEN).map_err(|e| format!("entropy source failed: {e}"))?;
    let plan = build_target_plan(&target, &password);

    if plan.mode == Mode::DryRun {
        let json = serde_json::to_string_pretty(&plan).map_err(|e| e.to_string())?;
        println!("{json}");
        return Ok(());
    }

    let auth = resolve_auth();
    println!("mqtt_username={}", plan.mqtt_username);
    println!("mqtt_password={password}");
    let client = reqwest::Client::builder()
        .timeout(APPLY_TIMEOUT)
        .build()
        .map_err(|e| format!("http client: {e}"))?;
    apply_plan(&client, &plan, &auth).await?;
    println!(
        "applied {} steps for {}",
        plan.steps.len(),
        plan.principal_id
    );
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
    fn gate_role_has_legacy_and_v2_rules_with_exact_actions() {
        let rules = build_acl_rules("gate-01", Role::Gate);
        // 4 legacy gate rules + 4 v2 publish + 4 v2 subscribe = 12 total
        assert_eq!(rules.len(), 12);

        // Legacy access rules
        assert!(rules.iter().any(|r| r.action == Action::Publish
            && r.topic == "access/gate-01/auth"
            && r.permission == "allow"));
        assert!(rules.iter().any(|r| r.action == Action::Publish
            && r.topic == "access/gate-01/presence"
            && r.permission == "allow"));
        assert!(rules.iter().any(|r| r.action == Action::Subscribe
            && r.topic == "access/gate-01/cmd"
            && r.permission == "allow"));
        assert!(rules.iter().any(|r| r.action == Action::Subscribe
            && r.topic == "access/gate-01/acl"
            && r.permission == "allow"));

        // v2 publish rules: hello, tap, report, diag
        for subtopic in ["hello", "tap", "report", "diag"] {
            let topic = format!("keygate/v2/gate-01/{subtopic}");
            assert!(
                rules
                    .iter()
                    .any(|r| r.action == Action::Publish && r.topic == topic),
                "missing publish rule for {topic}"
            );
        }

        // v2 subscribe rules: ack, sync, commission, diag/drain
        for subtopic in ["ack", "sync", "commission", "diag/drain"] {
            let topic = format!("keygate/v2/gate-01/{subtopic}");
            assert!(
                rules
                    .iter()
                    .any(|r| r.action == Action::Subscribe && r.topic == topic),
                "missing subscribe rule for {topic}"
            );
        }

        // Commission topic MUST NOT be publishable by the device (Plan D3 hardening)
        assert!(
            !rules
                .iter()
                .any(|r| r.action == Action::Publish && r.topic == "keygate/v2/gate-01/commission"),
            "device must NEVER have publish permission on commission topic"
        );

        // No writer rules in gate role
        assert!(rules.iter().all(|r| !r.topic.starts_with("writer/")));
    }

    #[test]
    fn writer_role_adds_job_topics_in_both_directions() {
        let rules = build_acl_rules("w-01", Role::Writer);
        // 12 base (legacy + v2) + 2 writer = 14 rules
        assert_eq!(rules.len(), 14);

        // Base sets are preserved
        assert!(rules.iter().any(|r| r.topic == "access/w-01/auth"));
        assert!(rules.iter().any(|r| r.topic == "access/w-01/cmd"));
        assert!(rules.iter().any(|r| r.topic == "keygate/v2/w-01/hello"));
        assert!(rules.iter().any(|r| r.topic == "keygate/v2/w-01/ack"));

        // Job topic in both directions
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
    fn verifier_rules_match_protocol_contract() {
        let rules = build_verifier_acl_rules();
        // 6 subscribe + 6 publish = 12 total
        assert_eq!(rules.len(), 12);

        // Subscriptions
        let expected_subs = [
            "keygate/v2/+/hello",
            "keygate/v2/+/tap",
            "keygate/v2/+/report",
            "access/+/presence",
            "writer/+/claim",
            "writer/+/done",
        ];
        for topic in expected_subs {
            assert!(
                rules.iter().any(|r| r.action == Action::Subscribe
                    && r.topic == topic
                    && r.permission == "allow"),
                "verifier missing subscribe rule for {topic}"
            );
        }

        // Publications
        let expected_pubs = [
            "keygate/v2/+/ack",
            "keygate/v2/+/sync",
            "keygate/v2/+/commission",
            "writer/+/job",
            "access/+/cmd",
            "access/+/acl",
        ];
        for topic in expected_pubs {
            assert!(
                rules.iter().any(|r| r.action == Action::Publish
                    && r.topic == topic
                    && r.permission == "allow"),
                "verifier missing publish rule for {topic}"
            );
        }

        // Commission topic MUST be publish-only for verifier
        assert!(
            rules
                .iter()
                .any(|r| r.action == Action::Publish && r.topic == "keygate/v2/+/commission"),
            "verifier must be permitted to publish commission"
        );
        assert!(
            !rules
                .iter()
                .any(|r| r.action == Action::Subscribe && r.topic == "keygate/v2/+/commission"),
            "verifier does not subscribe to commission"
        );
    }

    #[test]
    fn device_and_verifier_commission_rules_are_strictly_complementary() {
        let device_rules = build_acl_rules("dev-99", Role::Gate);
        let verifier_rules = build_verifier_acl_rules();

        // Device subscribes, does not publish
        assert!(device_rules
            .iter()
            .any(|r| r.action == Action::Subscribe && r.topic == "keygate/v2/dev-99/commission"));
        assert!(!device_rules
            .iter()
            .any(|r| r.action == Action::Publish && r.topic == "keygate/v2/dev-99/commission"));

        // Verifier publishes, does not subscribe
        assert!(verifier_rules
            .iter()
            .any(|r| r.action == Action::Publish && r.topic == "keygate/v2/+/commission"));
        assert!(!verifier_rules
            .iter()
            .any(|r| r.action == Action::Subscribe && r.topic == "keygate/v2/+/commission"));
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
    fn user_payload_uses_principal_id_as_username() {
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
        assert_eq!(arr[0]["rules"].as_array().expect("rules").len(), 12);
    }

    #[test]
    fn verifier_acl_entry_has_correct_username_scope() {
        let entry = build_verifier_acl_entry("verifier-svc");
        let value = serde_json::to_value(vec![entry]).expect("serializable");
        let arr = value.as_array().expect("array body");
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["username"], "verifier-svc");
        assert_eq!(arr[0]["rules"].as_array().expect("rules").len(), 12);
    }

    fn cli_device(device_id: &str, role: Role, apply: bool) -> Cli {
        Cli {
            command: None,
            device_id: Some(device_id.to_owned()),
            role,
            verifier: false,
            verifier_id: "verifier".to_owned(),
            dry_run: false,
            apply,
            api_url: "http://localhost:18083/".to_owned(),
        }
    }

    fn cli_verifier(verifier_id: &str, apply: bool) -> Cli {
        Cli {
            command: None,
            device_id: None,
            role: Role::Gate,
            verifier: true,
            verifier_id: verifier_id.to_owned(),
            dry_run: false,
            apply,
            api_url: "http://localhost:18083/".to_owned(),
        }
    }

    #[test]
    fn dry_run_device_plan_json_parses_and_round_trips() {
        let plan = build_plan(
            &cli_device("gate-9", Role::Gate, false),
            "Abcdefghijklmnopqrstuvwxyz012345",
        );
        let json = serde_json::to_string(&plan).expect("serializable");
        let back: Plan = serde_json::from_str(&json).expect("parses");
        assert_eq!(plan, back);
        assert_eq!(plan.principal_kind, PrincipalKind::Device);
        assert_eq!(plan.principal_id, "gate-9");
        assert_eq!(plan.role, Some(Role::Gate));
        assert_eq!(plan.mode, Mode::DryRun);
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

    #[test]
    fn dry_run_verifier_plan_json_parses_and_round_trips() {
        let plan = build_plan(
            &cli_verifier("verifier", false),
            "Abcdefghijklmnopqrstuvwxyz012345",
        );
        let json = serde_json::to_string(&plan).expect("serializable");
        let back: Plan = serde_json::from_str(&json).expect("parses");
        assert_eq!(plan, back);
        assert_eq!(plan.principal_kind, PrincipalKind::Verifier);
        assert_eq!(plan.principal_id, "verifier");
        assert_eq!(plan.role, None);
        assert_eq!(plan.mode, Mode::DryRun);
        assert_eq!(json.matches("Abcdefghijklmnopqrstuvwxyz012345").count(), 1);
        assert!(plan.steps[0].url.ends_with(USER_ENDPOINT));
        assert!(plan.steps[1].url.ends_with(ACL_ENDPOINT));
    }

    #[test]
    fn subcommand_parsing_produces_identical_target_config() {
        let cmd_dev = Cli {
            command: Some(Command::Device(DeviceArgs {
                device_id: "frontdoor".to_owned(),
                role: Role::Gate,
                dry_run: false,
                apply: true,
                api_url: "http://127.0.0.1:18083".to_owned(),
            })),
            device_id: None,
            role: Role::Gate,
            verifier: false,
            verifier_id: "verifier".to_owned(),
            dry_run: false,
            apply: false,
            api_url: "http://localhost:18083".to_owned(),
        };
        let target = TargetConfig::from_cli(&cmd_dev).expect("target config");
        assert_eq!(
            target,
            TargetConfig::Device {
                device_id: "frontdoor".to_owned(),
                role: Role::Gate,
                apply: true,
                api_url: "http://127.0.0.1:18083".to_owned()
            }
        );

        let cmd_ver = Cli {
            command: Some(Command::Verifier(VerifierArgs {
                verifier_id: "acv-prod".to_owned(),
                dry_run: true,
                apply: true,
                api_url: "http://127.0.0.1:18083".to_owned(),
            })),
            device_id: None,
            role: Role::Gate,
            verifier: false,
            verifier_id: "verifier".to_owned(),
            dry_run: false,
            apply: false,
            api_url: "http://localhost:18083".to_owned(),
        };
        let target_ver = TargetConfig::from_cli(&cmd_ver).expect("target config");
        assert_eq!(
            target_ver,
            TargetConfig::Verifier {
                verifier_id: "acv-prod".to_owned(),
                apply: false, // dry_run takes precedence
                api_url: "http://127.0.0.1:18083".to_owned()
            }
        );
    }

    #[test]
    fn apply_flag_selects_apply_mode_otherwise_dry_run() {
        assert_eq!(
            build_plan(&cli_device("d", Role::Gate, true), "pw").mode,
            Mode::Apply
        );
        assert_eq!(
            build_plan(&cli_device("d", Role::Gate, false), "pw").mode,
            Mode::DryRun
        );
        let mut conflicting = cli_device("d", Role::Gate, true);
        conflicting.dry_run = true;
        assert_eq!(build_plan(&conflicting, "pw").mode, Mode::DryRun);
    }
}
