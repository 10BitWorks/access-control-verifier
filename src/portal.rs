use crate::api::AppState;
use crate::crypto::{diversify, verify_sun, SunCmac, TapCounter, Uid};
use crate::store::{AccessDecision, TapOutcome};
use crate::writer::job_payload;
use axum::{
    extract::{FromRequestParts, Query, State},
    http::{header, request::Parts, HeaderMap, StatusCode},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
    Json, Router,
};
use cookie::Cookie;
use jsonwebtoken::{
    jwk::{AlgorithmParameters, Jwk, JwkSet, PublicKeyUse},
    Algorithm, DecodingKey, EncodingKey, Header, Validation,
};
use oauth2::{
    basic::{
        BasicErrorResponse, BasicRevocationErrorResponse, BasicTokenIntrospectionResponse,
        BasicTokenType,
    },
    AuthUrl, AuthorizationCode, Client, ClientId, ClientSecret, CsrfToken, EndpointNotSet,
    ExtraTokenFields, PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, Scope,
    StandardRevocableToken, StandardTokenResponse, TokenUrl,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::env;
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub const SESSION_COOKIE_NAME: &str = "keygate_session";
pub const OIDC_COOKIE_NAME: &str = "keygate_oidc_flow";

/// OIDC & Portal Configuration from environment.
#[derive(Clone, Debug)]
pub struct OidcConfig {
    pub issuer: String,
    pub client_id: String,
    pub client_secret: String,
    pub public_url: String,
    pub session_secret: String,
    pub session_lifetime_hours: i64,
    pub admin_role: String,
}

impl OidcConfig {
    pub fn from_env() -> Option<Self> {
        let issuer = env::var("AUTHENTIK_ISSUER")
            .ok()?
            .trim()
            .trim_end_matches('/')
            .to_string();
        let client_id = env::var("AUTHENTIK_CLIENT_ID").ok()?.trim().to_string();
        let client_secret = env::var("AUTHENTIK_CLIENT_SECRET").ok()?.trim().to_string();
        let public_url = env::var("PUBLIC_URL")
            .ok()?
            .trim()
            .trim_end_matches('/')
            .to_string();

        if issuer.is_empty()
            || client_id.is_empty()
            || client_secret.is_empty()
            || public_url.is_empty()
        {
            return None;
        }

        let session_secret = env::var("SESSION_SECRET")
            .unwrap_or_else(|_| "insecure-dev-session-secret-change-me".to_string());
        let session_lifetime_hours = env::var("SESSION_LIFETIME_HOURS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(12);
        let admin_role = env::var("ADMIN_ROLE").unwrap_or_else(|_| "Onboarder".to_string());

        Some(Self {
            issuer,
            client_id,
            client_secret,
            public_url,
            session_secret,
            session_lifetime_hours,
            admin_role,
        })
    }
}

#[derive(Clone)]
pub struct PortalState {
    pub app_state: AppState,
    pub oidc_config: Option<OidcConfig>,
    pub http_client: reqwest::Client,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionClaims {
    pub sub: String,
    pub username: String,
    pub roles: Vec<String>,
    pub exp: usize,
    pub iat: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Principal {
    pub username: String,
    pub roles: Vec<String>,
    pub is_admin: bool,
}

impl Principal {
    pub fn is_admin(&self) -> bool {
        self.is_admin
    }
}

pub fn verify_session_token(token: &str, secret: &str, admin_role: &str) -> Option<Principal> {
    let key = DecodingKey::from_secret(secret.as_bytes());
    let mut validation = Validation::new(jsonwebtoken::Algorithm::HS256);
    validation.validate_exp = true;
    let token_data = jsonwebtoken::decode::<SessionClaims>(token, &key, &validation).ok()?;
    let is_admin = token_data.claims.roles.iter().any(|r| r == admin_role);
    Some(Principal {
        username: token_data.claims.username,
        roles: token_data.claims.roles,
        is_admin,
    })
}

pub fn extract_session_from_headers(
    headers: &HeaderMap,
    secret: &str,
    admin_role: &str,
) -> Option<Principal> {
    if let Some(cookie_hdr) = headers.get(header::COOKIE) {
        if let Ok(cookie_str) = cookie_hdr.to_str() {
            for cookie in cookie_str.split(';') {
                let cookie = cookie.trim();
                if let Some(val) = cookie.strip_prefix(&format!("{SESSION_COOKIE_NAME}=")) {
                    if let Some(principal) = verify_session_token(val, secret, admin_role) {
                        return Some(principal);
                    }
                }
            }
        }
    }
    None
}

// Axum extractor for authenticated portal session
impl<S> FromRequestParts<S> for Principal
where
    S: Send + Sync,
    AppState: FromRef<S>,
    Option<OidcConfig>: FromRef<S>,
{
    type Rejection = (StatusCode, Response);

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let oidc_config = Option::<OidcConfig>::from_ref(state);
        let Some(cfg) = oidc_config else {
            return Err((
                StatusCode::SERVICE_UNAVAILABLE,
                "OIDC not configured".into_response(),
            ));
        };

        if let Some(principal) =
            extract_session_from_headers(&parts.headers, &cfg.session_secret, &cfg.admin_role)
        {
            Ok(principal)
        } else {
            Err((
                StatusCode::UNAUTHORIZED,
                Json(json!({ "error": "unauthorized", "login_url": "/auth/login" }))
                    .into_response(),
            ))
        }
    }
}

// Axum FromRef helper traits for PortalState
pub trait FromRef<T> {
    fn from_ref(input: &T) -> Self;
}

impl FromRef<PortalState> for AppState {
    fn from_ref(state: &PortalState) -> Self {
        state.app_state.clone()
    }
}

impl FromRef<PortalState> for Option<OidcConfig> {
    fn from_ref(state: &PortalState) -> Self {
        state.oidc_config.clone()
    }
}

/// OpenID Provider metadata from `/.well-known/openid-configuration`
#[derive(Debug, Deserialize)]
struct OpenIdConfig {
    authorization_endpoint: String,
    token_endpoint: String,
    #[serde(default)]
    jwks_uri: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OpenIdTokenFields {
    #[serde(default)]
    pub id_token: Option<String>,
}

impl ExtraTokenFields for OpenIdTokenFields {}

pub type OpenIdTokenResponse = StandardTokenResponse<OpenIdTokenFields, BasicTokenType>;

pub type OpenIdClient<
    HasAuthUrl = EndpointNotSet,
    HasDeviceAuthUrl = EndpointNotSet,
    HasIntrospectionUrl = EndpointNotSet,
    HasRevocationUrl = EndpointNotSet,
    HasTokenUrl = EndpointNotSet,
> = Client<
    BasicErrorResponse,
    OpenIdTokenResponse,
    BasicTokenIntrospectionResponse,
    StandardRevocableToken,
    BasicRevocationErrorResponse,
    HasAuthUrl,
    HasDeviceAuthUrl,
    HasIntrospectionUrl,
    HasRevocationUrl,
    HasTokenUrl,
>;

#[derive(Debug, Serialize, Deserialize)]
struct OidcFlowCookie {
    pkce_verifier: String,
    csrf_token: String,
    nonce: String,
}

#[derive(Debug, Deserialize)]
struct IdTokenClaims {
    // iss/aud/exp are not fields here: they are enforced by `Validation`
    // inside `verify_id_token`; unknown claims are ignored on deserialize.
    #[serde(default)]
    nonce: Option<String>,
    #[serde(default)]
    preferred_username: Option<String>,
    #[serde(default)]
    roles: Option<Vec<String>>,
    #[serde(default)]
    groups: Option<Vec<String>>,
}

/// Cached JWKS document plus its endpoint URL and fetch time.
struct JwksCache {
    url: String,
    keys: JwkSet,
    fetched_at: Instant,
}

/// Process-wide JWKS cache; entries are refetched when older than
/// [`JWKS_MAX_AGE`] or when a token references an unknown `kid`.
static JWKS_CACHE: Mutex<Option<JwksCache>> = Mutex::new(None);

const JWKS_MAX_AGE: Duration = Duration::from_secs(3600);

fn cached_jwks(url: &str) -> Option<JwkSet> {
    let guard = JWKS_CACHE.lock().ok()?;
    let cache = guard.as_ref()?;
    (cache.url == url && cache.fetched_at.elapsed() < JWKS_MAX_AGE).then(|| cache.keys.clone())
}

async fn fetch_jwks(state: &PortalState, url: &str) -> Result<JwkSet, Box<Response>> {
    let keys: JwkSet = match state.http_client.get(url).send().await {
        Ok(res) if res.status().is_success() => match res.json().await {
            Ok(keys) => keys,
            Err(e) => {
                tracing::error!(error = %e, "Failed to parse JWKS");
                return Err(Box::new(
                    (StatusCode::BAD_GATEWAY, "JWKS parse error").into_response(),
                ));
            }
        },
        Ok(res) => {
            tracing::error!(status = %res.status(), "JWKS endpoint returned error");
            return Err(Box::new(
                (StatusCode::BAD_GATEWAY, "JWKS fetch failed").into_response(),
            ));
        }
        Err(e) => {
            tracing::error!(error = %e, "Failed to reach JWKS endpoint");
            return Err(Box::new(
                (StatusCode::BAD_GATEWAY, "Failed to reach JWKS endpoint").into_response(),
            ));
        }
    };
    if let Ok(mut guard) = JWKS_CACHE.lock() {
        *guard = Some(JwksCache {
            url: url.to_string(),
            keys: keys.clone(),
            fetched_at: Instant::now(),
        });
    }
    Ok(keys)
}

/// Pick the RSA signing key matching the token's `kid` (any RSA signing key
/// when the token header omits `kid`).
fn signing_jwk<'a>(keys: &'a JwkSet, kid: Option<&str>) -> Option<&'a Jwk> {
    keys.keys.iter().find(|jwk| {
        matches!(jwk.algorithm, AlgorithmParameters::RSA(_))
            && jwk.common.public_key_use != Some(PublicKeyUse::Encryption)
            && kid.is_none_or(|k| jwk.common.key_id.as_deref() == Some(k))
    })
}

/// Verify an OIDC ID token's RS256 signature against the issuer's JWKS and
/// enforce iss/aud/exp via `Validation`. On an unknown `kid`, refreshes the
/// JWKS once (key rollover) before failing.
async fn verify_id_token(
    state: &PortalState,
    cfg: &OidcConfig,
    jwks_uri: &str,
    id_token: &str,
) -> Result<IdTokenClaims, Box<Response>> {
    let header = jsonwebtoken::decode_header(id_token).map_err(|e| {
        tracing::warn!(error = %e, "ID token header decode failed");
        (
            StatusCode::UNAUTHORIZED,
            format!("ID token header invalid: {e}"),
        )
            .into_response()
    })?;

    let keys = match cached_jwks(jwks_uri) {
        Some(keys) => keys,
        None => fetch_jwks(state, jwks_uri).await?,
    };

    let kid = header.kid.as_deref();
    let mut jwk = signing_jwk(&keys, kid).cloned();
    if jwk.is_none() {
        // Unknown or missing kid: force one JWKS refresh (key rollover) and retry.
        let keys = fetch_jwks(state, jwks_uri).await?;
        jwk = signing_jwk(&keys, kid).cloned();
    }
    let jwk = jwk.ok_or(
        (
            StatusCode::UNAUTHORIZED,
            "ID token signing key not found in JWKS",
        )
            .into_response(),
    )?;

    let decoding_key = DecodingKey::from_jwk(&jwk).map_err(|e| {
        tracing::warn!(error = %e, "JWK to decoding key conversion failed");
        (StatusCode::UNAUTHORIZED, "ID token signing key invalid").into_response()
    })?;

    let mut validation = Validation::new(Algorithm::RS256);
    // Accept the issuer with and without a trailing slash: OIDC-issued `iss`
    // values (Authentik's included) frequently carry it, while operators
    // configure `AUTHENTIK_ISSUER` without one. `from_env` trims it for URL
    // construction, so normalize both directions here.
    validation.iss = Some([cfg.issuer.clone(), format!("{}/", cfg.issuer)].into());
    validation.aud = Some([cfg.client_id.clone()].into());
    validation.validate_exp = true;

    let token_data = jsonwebtoken::decode::<IdTokenClaims>(id_token, &decoding_key, &validation)
        .map_err(|e| {
            tracing::warn!(error = %e, "ID token validation failed");
            (StatusCode::UNAUTHORIZED, format!("ID token invalid: {e}")).into_response()
        })?;

    Ok(token_data.claims)
}

pub fn router(app_state: AppState) -> Router {
    let oidc_config = OidcConfig::from_env();
    let portal_state = PortalState {
        app_state,
        oidc_config,
        http_client: reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(15))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap_or_default(),
    };

    Router::new()
        .route("/", get(root_handler))
        .route("/tap/report-lost", post(tap_report_lost))
        .route("/auth/login", get(auth_login))
        .route("/auth/callback", get(auth_callback))
        .route("/auth/logout", post(auth_logout))
        .route("/me", get(me_ui))
        .route("/me/api/status", get(me_status))
        .route("/me/provision", post(me_provision))
        .route("/me/revoke", post(me_revoke))
        .route("/me/api/taps", get(me_taps))
        .with_state(portal_state)
}

// ---------------------------------------------------------------------------
// SUN tap landing (public): a tapped NTAG 424 DNA card opens
// https://keys.10bitworks.org/?uid=..&c=..&cmac=.. and the holder sees the
// key's identity, live tap counter, and self-service actions — no sign-in
// required. Possession of a valid (uid, counter, CMAC) triple IS the card.
// ---------------------------------------------------------------------------

/// NTAG 424 SUN tap counters are 24-bit.
const TAP_MAX_COUNTER: u64 = 0xFF_FFFF;

fn query_param<'q>(query: &'q str, name: &str) -> Option<&'q str> {
    query.split('&').find_map(|pair| {
        let (k, v) = pair.split_once('=')?;
        (k == name).then_some(v)
    })
}

async fn root_handler(State(state): State<PortalState>, req: axum::extract::Request) -> Response {
    let query = req.uri().query().unwrap_or("");
    match (
        query_param(query, "uid"),
        query_param(query, "c"),
        query_param(query, "cmac"),
    ) {
        (Some(uid), Some(c), Some(cmac)) => {
            tap_landing(state, uid.to_string(), c.to_string(), cmac.to_string()).await
        }
        _ => Redirect::to("/me").into_response(),
    }
}

/// Minimal HTML escaping for template interpolation.
fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#x27;"),
            _ => out.push(ch),
        }
    }
    out
}

/// The generic "not recognized" page. Deliberately IDENTICAL for parse
/// failures, unknown UIDs, and CMAC mismatches so the endpoint cannot be
/// used as a validity oracle for guessed UIDs.
fn tap_generic_page() -> Response {
    Html(
        include_str!("tap.html")
            .replace(
                "__GENERIC_BLOCK__",
                r#"<div class="card">
                <div class="card-header">
                    <h2>Unrecognized Key</h2>
                    <span class="card-ref">FIG. 00 · DENIED</span>
                </div>
                <p style="margin:0;">This key link is not recognized. If this is your card, contact a 10BitWorks admin, or sign in to the member portal.</p>
                <div class="actions" style="margin-top:16px;">
                    <a class="btn btn-primary" href="/auth/login">Sign In</a>
                </div>
            </div>"#,
            )
            .replace("__MEMBER_NAME__", "")
            .replace("__PHONE__", "")
            .replace("__PHONE_HIDDEN__", "hidden")
            .replace("__STATUS__", "")
            .replace("__STATUS_CLASS__", "")
            .replace("__STALE_NOTICE__", "")
            .replace("__COUNTER__", "")
            .replace("__ENROLLED__", "")
            .replace("__KEY_VERSION__", "")
            .replace("__UID__", "")
            .replace("__C__", "")
            .replace("__CMAC__", ""),
    )
    .into_response()
}

async fn tap_landing(state: PortalState, uid_hex: String, c: String, cmac_hex: String) -> Response {
    let Ok(uid) = Uid::from_hex(&uid_hex) else {
        return tap_generic_page();
    };
    let Ok(tap_counter) = TapCounter::from_hex(&c) else {
        return tap_generic_page();
    };
    let Ok(cmac) = SunCmac::from_hex(&cmac_hex) else {
        return tap_generic_page();
    };
    let counter_u64 = tap_counter.to_u32() as u64;
    if counter_u64 > TAP_MAX_COUNTER {
        return tap_generic_page();
    }

    let now = chrono::Utc::now().to_rfc3339();

    // Validate + record inside one store lock, mirroring the MQTT auth path.
    let tap_view = {
        let mut store = state.app_state.store.lock().expect("store lock poisoned");
        let Some(tag) = store.tag_by_uid(&uid_hex).ok().flatten() else {
            return tap_generic_page();
        };
        let tag_key = diversify(&state.app_state.master, &uid);
        if verify_sun(&uid, &tap_counter, &cmac, &tag_key).is_err() {
            return tap_generic_page();
        }

        let decision = store
            .effective_access(&uid_hex, &now)
            .unwrap_or_else(|e| {
                tracing::warn!(error = %e, "effective_access failed");
                AccessDecision::Denied("member_inactive".to_string())
            });
        let outcome = store
            .record_tap(&uid_hex, counter_u64 as i64, Some("web-tap"), &now, decision.clone())
            .unwrap_or_else(|e| {
                tracing::warn!(error = %e, "record_tap failed");
                TapOutcome::Denied("member_inactive".to_string())
            });

        let (stale, shown_counter) = match &outcome {
            TapOutcome::Granted => (false, counter_u64 as i64),
            TapOutcome::Denied(reason) if reason == "counter_replay" => {
                // Stale link (counter already seen): still show the page, but
                // display the card's authoritative stored counter.
                let last = store
                    .tag_by_uid(&uid_hex)
                    .ok()
                    .flatten()
                    .map(|t| t.last_counter)
                    .unwrap_or(counter_u64 as i64);
                (true, last)
            }
            TapOutcome::Denied(_) => (false, counter_u64 as i64),
        };

        let contact = store.member_contact(&tag.member_key).ok().flatten();
        (tag, decision, stale, shown_counter, contact)
    };

    let (tag, decision, stale, shown_counter, contact) = tap_view;
    let (member_name, phone) = contact
        .map(|(name, phone)| (if name.is_empty() { tag.member_key.clone() } else { name }, phone))
        .unwrap_or_else(|| (tag.member_key.clone(), None));

    let (status_label, status_class) = if tag.status != "active" {
        ("Deactivated", "badge-expired")
    } else {
        match &decision {
            AccessDecision::Granted => ("Active", "badge-active"),
            AccessDecision::Denied(_) => ("Expired", "badge-expired"),
        }
    };

    let stale_notice = if stale {
        r#"<p class="notice">This tap link was already scanned — showing the card's stored counter.</p>"#
    } else {
        ""
    };

    Html(
        include_str!("tap.html")
            .replace("__GENERIC_BLOCK__", "")
            .replace(
                "<div id=\"tap-content\" style=\"display:none;\">",
                "<div id=\"tap-content\">",
            )
            .replace("__MEMBER_NAME__", &html_escape(&member_name))
            .replace(
                "__PHONE__",
                &html_escape(phone.as_deref().unwrap_or("")),
            )
            .replace("__PHONE_HIDDEN__", if phone.is_some() { "" } else { "hidden" })
            .replace("__STATUS__", status_label)
            .replace("__STATUS_CLASS__", status_class)
            .replace("__STALE_NOTICE__", stale_notice)
            .replace("__COUNTER__", &html_escape(&shown_counter.to_string()))
            .replace("__ENROLLED__", &html_escape(&tag.enrolled_at))
            .replace("__KEY_VERSION__", &html_escape(&tag.key_version.to_string()))
            .replace("__UID__", &html_escape(&uid_hex))
            .replace("__C__", &html_escape(&c))
            .replace("__CMAC__", &html_escape(&cmac_hex)),
    )
    .into_response()
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReportLostBody {
    uid: String,
    c: String,
    cmac: String,
}

/// Instant de-provisioning from the tap landing page. Re-validates the SUN
/// CMAC (possession of the card == possession of the triple), then revokes
/// the tag and notifies Slack. Replay-tolerant by design: the GET already
/// recorded the counter, so the same triple is accepted here without
/// recording a second tap.
async fn tap_report_lost(
    State(state): State<PortalState>,
    Json(body): Json<ReportLostBody>,
) -> Response {
    let Ok(uid) = Uid::from_hex(&body.uid) else {
        return (StatusCode::BAD_REQUEST, Json(json!({"ok": false, "error": "unrecognized key"}))).into_response();
    };
    let Ok(tap_counter) = TapCounter::from_hex(&body.c) else {
        return (StatusCode::BAD_REQUEST, Json(json!({"ok": false, "error": "unrecognized key"}))).into_response();
    };
    let Ok(cmac) = SunCmac::from_hex(&body.cmac) else {
        return (StatusCode::BAD_REQUEST, Json(json!({"ok": false, "error": "unrecognized key"}))).into_response();
    };
    let counter_i64 = tap_counter.to_u32() as i64;

    let (member_key, member_name) = {
        let mut store = state.app_state.store.lock().expect("store lock poisoned");
        let Some(tag) = store.tag_by_uid(&body.uid).ok().flatten() else {
            return (StatusCode::NOT_FOUND, Json(json!({"ok": false, "error": "unrecognized key"}))).into_response();
        };
        let tag_key = diversify(&state.app_state.master, &uid);
        if verify_sun(&uid, &tap_counter, &cmac, &tag_key).is_err() {
            return (StatusCode::NOT_FOUND, Json(json!({"ok": false, "error": "unrecognized key"}))).into_response();
        }
        if tag.status != "active" {
            return (
                StatusCode::OK,
                Json(json!({"ok": true, "message": "Key was already deactivated."})),
            )
                .into_response();
        }
        if let Err(e) = store.revoke_tag(&body.uid) {
            tracing::warn!(error = %e, "revoke_tag failed");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"ok": false, "error": "deactivation failed; try again"})),
            )
                .into_response();
        }
        let now = chrono::Utc::now().to_rfc3339();
        let _ = store.audit_event(
            &now,
            Some("web-tap"),
            Some(&body.uid),
            Some(counter_i64),
            "denied",
            "reported_lost",
        );
        let name = store
            .member_contact(&tag.member_key)
            .ok()
            .flatten()
            .map(|(n, _)| n)
            .unwrap_or_else(|| tag.member_key.clone());
        (tag.member_key, name)
    };

    notify_slack(
        &state.http_client,
        format!(
            ":key: *Lost key reported* — {}'s card `{}` was deactivated instantly after a web tap ({}, member `{}`).",
            member_name, body.uid, chrono::Utc::now().to_rfc3339(), member_key
        ),
    )
    .await;

    (
        StatusCode::OK,
        Json(json!({"ok": true, "message": "Key deactivated"})),
    )
        .into_response()
}

/// Fire-and-forget Slack webhook post. Disabled when SLACK_WEBHOOK_URL is
/// unset; failures are logged, never propagated.
async fn notify_slack(client: &reqwest::Client, text: String) {
    let Ok(url) = env::var("SLACK_WEBHOOK_URL") else {
        tracing::warn!("SLACK_WEBHOOK_URL not set; Slack notification skipped");
        return;
    };
    if url.is_empty() {
        tracing::warn!("SLACK_WEBHOOK_URL empty; Slack notification skipped");
        return;
    }
    let client = client.clone();
    tokio::spawn(async move {
        match client.post(&url).json(&json!({ "text": text })).send().await {
            Ok(res) if res.status().is_success() => {}
            Ok(res) => tracing::warn!(status = %res.status(), "Slack webhook post failed"),
            Err(e) => tracing::warn!(error = %e, "Slack webhook post failed"),
        }
    });
}

async fn not_configured_page() -> Html<&'static str> {
    Html(
        r#"<!DOCTYPE html>
<html>
<head><title>Portal Not Configured</title><style>body{font-family:sans-serif;margin:40px;line-height:1.5;}</style></head>
<body>
    <h1>Key Portal Not Configured</h1>
    <p>OIDC authentication environment variables are not set on this server.</p>
    <p>Admin API remains accessible via configured bearer token at <a href="/admin">/admin</a>.</p>
</body>
</html>"#,
    )
}

async fn auth_login(State(state): State<PortalState>) -> Response {
    let Some(cfg) = state.oidc_config.as_ref() else {
        return not_configured_page().await.into_response();
    };

    let discovery_url = format!("{}/.well-known/openid-configuration", cfg.issuer);
    let discovery: OpenIdConfig = match state.http_client.get(&discovery_url).send().await {
        Ok(res) if res.status().is_success() => match res.json().await {
            Ok(c) => c,
            Err(e) => {
                tracing::error!(error = %e, "Failed to parse OIDC discovery");
                return (StatusCode::BAD_GATEWAY, "OIDC discovery parse error").into_response();
            }
        },
        Ok(res) => {
            tracing::error!(status = %res.status(), "OIDC discovery failed");
            return (StatusCode::BAD_GATEWAY, "OIDC discovery HTTP failure").into_response();
        }
        Err(e) => {
            tracing::error!(error = %e, "Failed to reach OIDC issuer");
            return (StatusCode::BAD_GATEWAY, "Failed to reach OIDC issuer").into_response();
        }
    };

    let auth_url = match AuthUrl::new(discovery.authorization_endpoint) {
        Ok(u) => u,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };
    let token_url = match TokenUrl::new(discovery.token_endpoint) {
        Ok(u) => u,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };

    let redirect_url = match RedirectUrl::new(format!("{}/auth/callback", cfg.public_url)) {
        Ok(u) => u,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };

    let client = OpenIdClient::new(ClientId::new(cfg.client_id.clone()))
        .set_client_secret(ClientSecret::new(cfg.client_secret.clone()))
        .set_auth_uri(auth_url)
        .set_token_uri(token_url)
        .set_redirect_uri(redirect_url);

    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
    let (authorize_url, csrf_token) = client
        .authorize_url(CsrfToken::new_random)
        .add_scope(Scope::new("openid".to_string()))
        .add_scope(Scope::new("profile".to_string()))
        .add_scope(Scope::new("email".to_string()))
        .add_scope(Scope::new("roles".to_string()))
        .set_pkce_challenge(pkce_challenge)
        .url();

    let nonce = CsrfToken::new_random().secret().to_string();
    let mut url_with_nonce = authorize_url;
    url_with_nonce
        .query_pairs_mut()
        .append_pair("nonce", &nonce);

    let flow_state = OidcFlowCookie {
        pkce_verifier: pkce_verifier.secret().to_string(),
        csrf_token: csrf_token.secret().to_string(),
        nonce,
    };

    let is_https = cfg.public_url.starts_with("https://");
    use base64::Engine;
    let flow_raw_json = serde_json::to_string(&flow_state).unwrap_or_default();
    let flow_b64 =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(flow_raw_json.as_bytes());
    let flow_cookie = Cookie::build((OIDC_COOKIE_NAME, flow_b64))
        .path("/auth/callback")
        .http_only(true)
        .same_site(cookie::SameSite::Lax)
        .secure(is_https)
        .max_age(cookie::time::Duration::minutes(15))
        .build();

    let mut response = Redirect::to(url_with_nonce.as_str()).into_response();
    if let Ok(hdr) = flow_cookie.to_string().parse() {
        response.headers_mut().append(header::SET_COOKIE, hdr);
    }
    response
}

#[derive(Deserialize)]
struct CallbackParams {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
}

async fn auth_callback(
    State(state): State<PortalState>,
    headers: HeaderMap,
    Query(params): Query<CallbackParams>,
) -> Response {
    let Some(cfg) = state.oidc_config.as_ref() else {
        return not_configured_page().await.into_response();
    };

    if let Some(err) = params.error {
        let desc = params.error_description.unwrap_or_default();
        tracing::warn!(error = %err, desc = %desc, "OIDC authorization error");
        return (
            StatusCode::BAD_REQUEST,
            format!("Auth error: {err} ({desc})"),
        )
            .into_response();
    }

    let (Some(code), Some(ret_state)) = (params.code, params.state) else {
        return (StatusCode::BAD_REQUEST, "Missing code or state").into_response();
    };

    // Extract OIDC flow cookie
    let mut flow_cookie_str = None;
    if let Some(cookie_hdr) = headers.get(header::COOKIE) {
        if let Ok(s) = cookie_hdr.to_str() {
            for c in s.split(';') {
                let c = c.trim();
                if let Some(val) = c.strip_prefix(&format!("{OIDC_COOKIE_NAME}=")) {
                    flow_cookie_str = Some(val.to_string());
                }
            }
        }
    }

    let Some(flow_raw) = flow_cookie_str else {
        tracing::warn!(
            "OIDC callback missing flow cookie; redirecting to login to re-authenticate"
        );
        return (
            StatusCode::SEE_OTHER,
            [(header::LOCATION, "/auth/login")],
            "Session expired; redirecting to login...",
        )
            .into_response();
    };

    use base64::Engine;
    // Decode url-safe base64 or fall back to raw json for backward compatibility
    let flow_json = if let Ok(bytes) =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(flow_raw.trim_matches('"'))
    {
        String::from_utf8(bytes).unwrap_or_else(|_| flow_raw.clone())
    } else if let Ok(bytes) =
        base64::engine::general_purpose::STANDARD.decode(flow_raw.trim_matches('"'))
    {
        String::from_utf8(bytes).unwrap_or_else(|_| flow_raw.clone())
    } else {
        flow_raw
    };

    let flow: OidcFlowCookie = match serde_json::from_str(&flow_json) {
        Ok(f) => f,
        Err(_) => {
            tracing::warn!("Invalid flow cookie; redirecting to login");
            return (
                StatusCode::SEE_OTHER,
                [(header::LOCATION, "/auth/login")],
                "Invalid session state; redirecting to login...",
            )
                .into_response();
        }
    };

    if flow.csrf_token != ret_state {
        return (StatusCode::BAD_REQUEST, "CSRF state mismatch").into_response();
    }

    // Discover token endpoint
    let discovery_url = format!("{}/.well-known/openid-configuration", cfg.issuer);
    let discovery: OpenIdConfig = match state.http_client.get(&discovery_url).send().await {
        Ok(res) if res.status().is_success() => match res.json().await {
            Ok(c) => c,
            Err(e) => return (StatusCode::BAD_GATEWAY, e.to_string()).into_response(),
        },
        _ => return (StatusCode::BAD_GATEWAY, "OIDC discovery failed").into_response(),
    };

    let auth_url = match AuthUrl::new(discovery.authorization_endpoint) {
        Ok(u) => u,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };
    let token_url = match TokenUrl::new(discovery.token_endpoint) {
        Ok(u) => u,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };
    let redirect_url = match RedirectUrl::new(format!("{}/auth/callback", cfg.public_url)) {
        Ok(u) => u,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };

    let client = OpenIdClient::new(ClientId::new(cfg.client_id.clone()))
        .set_client_secret(ClientSecret::new(cfg.client_secret.clone()))
        .set_auth_uri(auth_url)
        .set_token_uri(token_url)
        .set_redirect_uri(redirect_url);

    let token_res = match client
        .exchange_code(AuthorizationCode::new(code))
        .set_pkce_verifier(PkceCodeVerifier::new(flow.pkce_verifier))
        .request_async(&state.http_client)
        .await
    {
        Ok(res) => res,
        Err(e) => {
            tracing::warn!(error = %e, "OIDC code exchange failed");
            return (
                StatusCode::UNAUTHORIZED,
                format!("Token exchange failed: {e}"),
            )
                .into_response();
        }
    };

    // Extract ID token
    let extra = token_res.extra_fields();
    let id_token_str = match &extra.id_token {
        Some(s) => s.as_str(),
        None => {
            return (StatusCode::BAD_GATEWAY, "Token response missing id_token").into_response();
        }
    };

    // Verify ID token signature via the issuer's JWKS; iss/aud/exp are
    // enforced by `Validation` inside verify_id_token.
    let Some(jwks_uri) = discovery.jwks_uri.as_deref() else {
        return (
            StatusCode::BAD_GATEWAY,
            "Discovery document missing jwks_uri",
        )
            .into_response();
    };

    let claims: IdTokenClaims = match verify_id_token(&state, cfg, jwks_uri, id_token_str).await {
        Ok(c) => c,
        Err(resp) => return *resp,
    };

    // Validate Nonce
    if claims.nonce.as_deref() != Some(&flow.nonce) {
        return (StatusCode::UNAUTHORIZED, "ID token nonce mismatch").into_response();
    }

    // Extract preferred_username
    let Some(username) = claims.preferred_username.filter(|u| !u.is_empty()) else {
        return (
            StatusCode::BAD_REQUEST,
            "ID token missing preferred_username claim",
        )
            .into_response();
    };

    // Extract roles (support custom `roles` claim or fallback to `groups`)
    let roles = claims.roles.or(claims.groups).unwrap_or_default();
    tracing::info!(username = %username, ?roles, "OIDC user authenticated, issuing session cookie");

    // New members must not wait for the hourly roster sync: if this user has
    // no roster record yet, run a sync cycle right now so /me shows membership
    // immediately. Failure to sync never blocks the login itself.
    if let Ok(sync_cfg) = crate::sync::SyncConfig::from_env() {
        if !sync_cfg.authentik_token.is_empty() && sync_cfg.authentik_token != "dummy" {
            let member_exists = state
                .app_state
                .store
                .lock()
                .ok()
                .and_then(|guard| guard.get_member(&username).ok())
                .flatten()
                .is_some();
            if !member_exists {
                match crate::sync::run_sync_cycle(state.app_state.store.clone(), &sync_cfg).await {
                    Ok(stats) => tracing::info!(
                        username = %username,
                        added_or_updated = stats.added_or_updated,
                        removed = stats.removed,
                        "roster sync on first portal login"
                    ),
                    Err(e) => tracing::warn!(
                        username = %username,
                        error = %e,
                        "roster sync on first portal login failed"
                    ),
                }
            }
        }
    }

    // Create session JWT
    let now_ts = chrono::Utc::now().timestamp() as usize;
    let exp = now_ts + (cfg.session_lifetime_hours as usize * 3600);
    let session_claims = SessionClaims {
        sub: username.clone(),
        username: username.clone(),
        roles,
        exp,
        iat: now_ts,
    };

    let session_jwt = match jsonwebtoken::encode(
        &Header::default(),
        &session_claims,
        &EncodingKey::from_secret(cfg.session_secret.as_bytes()),
    ) {
        Ok(j) => j,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };

    let is_https = cfg.public_url.starts_with("https://");
    let session_cookie = Cookie::build((SESSION_COOKIE_NAME, session_jwt))
        .path("/")
        .http_only(true)
        .same_site(cookie::SameSite::Lax)
        .secure(is_https)
        .max_age(cookie::time::Duration::hours(cfg.session_lifetime_hours))
        .build();

    // Clear flow cookie
    let clear_flow_cookie = Cookie::build((OIDC_COOKIE_NAME, ""))
        .path("/auth/callback")
        .http_only(true)
        .same_site(cookie::SameSite::Lax)
        .secure(is_https)
        .max_age(cookie::time::Duration::seconds(0))
        .build();

    let mut response = Redirect::to("/me").into_response();
    if let Ok(hdr) = session_cookie.to_string().parse() {
        response.headers_mut().append(header::SET_COOKIE, hdr);
    }
    if let Ok(hdr) = clear_flow_cookie.to_string().parse() {
        response.headers_mut().append(header::SET_COOKIE, hdr);
    }

    response
}

async fn auth_logout(State(state): State<PortalState>) -> Response {
    let is_https = state
        .oidc_config
        .as_ref()
        .map(|c| c.public_url.starts_with("https://"))
        .unwrap_or(false);

    let clear_cookie = Cookie::build((SESSION_COOKIE_NAME, ""))
        .path("/")
        .http_only(true)
        .same_site(cookie::SameSite::Lax)
        .secure(is_https)
        .max_age(cookie::time::Duration::seconds(0))
        .build();

    let mut response = Redirect::to("/me").into_response();
    if let Ok(hdr) = clear_cookie.to_string().parse() {
        response.headers_mut().append(header::SET_COOKIE, hdr);
    }
    response
}

async fn me_ui(State(state): State<PortalState>) -> Response {
    if state.oidc_config.is_none() {
        return not_configured_page().await.into_response();
    }
    Html(include_str!("me.html")).into_response()
}

// ---------------------------------------------------------------------------
// Backing JSON API for /me
// ---------------------------------------------------------------------------

async fn me_status(
    State(state): State<PortalState>,
    principal_res: Result<Principal, (StatusCode, Response)>,
) -> Response {
    let principal = match principal_res {
        Ok(p) => p,
        Err((status, resp)) => return (status, resp).into_response(),
    };

    let store = state.app_state.store.lock().expect("store lock poisoned");
    let now = chrono::Utc::now().to_rfc3339();

    let membership = store.get_member(&principal.username).unwrap_or(None);
    let is_active = store
        .is_member_active(&principal.username, &now)
        .unwrap_or(false);
    let active_tag = store
        .get_active_tag_for_member(&principal.username)
        .unwrap_or(None);
    let pending_job = store
        .pending_job_for_member(&principal.username, &now)
        .unwrap_or(None);
    let latest_job = store
        .latest_job_for_member(&principal.username)
        .unwrap_or(None);

    (
        StatusCode::OK,
        Json(json!({
            "principal": principal,
            "membership": membership,
            "is_active": is_active,
            "active_tag": active_tag,
            "pending_job": pending_job,
            "latest_job": latest_job,
        })),
    )
        .into_response()
}

async fn me_provision(
    State(state): State<PortalState>,
    principal_res: Result<Principal, (StatusCode, Response)>,
) -> Response {
    let principal = match principal_res {
        Ok(p) => p,
        Err((status, resp)) => return (status, resp).into_response(),
    };

    let now_dt = chrono::Utc::now();
    let now = now_dt.to_rfc3339();
    let ttl_secs: u64 = 60;
    let expires_at = (now_dt + chrono::Duration::seconds(ttl_secs as i64)).to_rfc3339();

    let (job_id, writer_devices) = {
        let mut store = state.app_state.store.lock().expect("store lock poisoned");

        // 1. Guard: member row must exist
        let member = match store.get_member(&principal.username) {
            Ok(Some(m)) => m,
            Ok(None) => {
                return (
                    StatusCode::UNPROCESSABLE_ENTITY,
                    Json(json!({ "error": "No membership record exists for your account" })),
                )
                    .into_response();
            }
            Err(e) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({ "error": e.to_string() })),
                )
                    .into_response();
            }
        };

        // 2. Guard: member must be active (under same rules as effective_access)
        let is_active = match store.is_member_active(&member.member_key, &now) {
            Ok(a) => a,
            Err(e) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({ "error": e.to_string() })),
                )
                    .into_response();
            }
        };

        if !is_active {
            return (
                StatusCode::FORBIDDEN,
                Json(json!({ "error": "Membership is inactive or expired; key cannot be provisioned" })),
            )
                .into_response();
        }

        // 3. Guard: at most one live pending job per member
        if let Ok(Some(_)) = store.pending_job_for_member(&principal.username, &now) {
            return (
                StatusCode::CONFLICT,
                Json(json!({ "error": "A provisioning job is already pending for your account" })),
            )
                .into_response();
        }

        // Create wildcard job: uid="" (bound on tap), device_id="*" (claimable at any writer)
        let job_id = match store.create_job("", &principal.username, "*", &now, &expires_at) {
            Ok(id) => id,
            Err(e) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({ "error": e.to_string() })),
                )
                    .into_response();
            }
        };

        // Audit the arming event (analogous to admin arming)
        let _ = store.audit_event(
            &now,
            Some("self-service"),
            None,
            None,
            "granted",
            "self_service_provision_armed",
        );

        let writer_devices = store.list_writer_devices().unwrap_or_default();
        (job_id, writer_devices)
    };

    // Deliver arming payload to all current writer devices (and wildcard target "*")
    let payload = job_payload("", "", &job_id, &expires_at);
    state.app_state.jobs.publish_job("*", &payload);
    for device_id in writer_devices {
        state.app_state.jobs.publish_job(&device_id, &payload);
    }

    (
        StatusCode::CREATED,
        Json(json!({
            "status": "ok",
            "job_id": job_id,
            "expires_at": expires_at,
            "ttl_secs": ttl_secs,
        })),
    )
        .into_response()
}

async fn me_revoke(
    State(state): State<PortalState>,
    principal_res: Result<Principal, (StatusCode, Response)>,
) -> Response {
    let principal = match principal_res {
        Ok(p) => p,
        Err((status, resp)) => return (status, resp).into_response(),
    };

    let now = chrono::Utc::now().to_rfc3339();
    let mut store = state.app_state.store.lock().expect("store lock poisoned");

    match store.revoke_active_tags_for_member(&principal.username) {
        Ok(revoked_uids) => {
            for uid in &revoked_uids {
                let _ = store.audit_event(
                    &now,
                    Some("self-service"),
                    Some(uid),
                    None,
                    "granted",
                    "self_service_tag_revoked",
                );
            }
            (
                StatusCode::OK,
                Json(json!({ "status": "ok", "revoked_uids": revoked_uids })),
            )
                .into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}

async fn me_taps(
    State(state): State<PortalState>,
    principal_res: Result<Principal, (StatusCode, Response)>,
) -> Response {
    let principal = match principal_res {
        Ok(p) => p,
        Err((status, resp)) => return (status, resp).into_response(),
    };

    let store = state.app_state.store.lock().expect("store lock poisoned");
    let tags = store
        .list_tags_for_member(&principal.username)
        .unwrap_or_default();
    let uids: Vec<String> = tags.into_iter().map(|t| t.uid).collect();

    match store.list_audit_for_uids(&uids, 25) {
        Ok(audit) => (StatusCode::OK, Json(audit)).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}
