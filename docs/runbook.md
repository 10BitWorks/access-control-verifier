# Operations Runbook

## EMQX Configuration

### Rule Engine & HTTP Connector

Readers publish SUN auth tuples over MQTT; the verifier receives them over HTTP
via an EMQX rule + connector (the verifier itself only **subscribes** to
`access/+/presence` and **publishes** decisions/ACLs — it does not subscribe to
auth topics).

1.  Open the EMQX Dashboard.
2.  Navigate to **Integration** -> **Connectors**.
3.  Create a new HTTP Connector:
    *   **Name:** `access_verifier`
    *   **Base URL:** `http://access-control-verifier:8000` (the service binds
        `:8000`; `compose.yaml` maps host `:8001` -> container `:8000`)
    *   **Method:** `POST`
    *   **Headers:**
        *   `Content-Type: application/json`
        *   `x-emqx-secret: <EMQX_SHARED_SECRET>` — **required**; the verifier
            returns `401` for any request whose `x-emqx-secret` does not equal
            its configured `EMQX_SHARED_SECRET`

    > **Cross-host deployments (current production topology):** when EMQX and
    > the verifier run on different hosts (broker LXC vs the docker LXC), the
    > container hostname does not resolve from the broker — the rule fires but
    > every HTTP request fails silently. Put the full routable URL, path
    > included, in the connector instead:
    > `http://<verifier-host>:8001/v1/auth` (deployed:
    > `http://10.7.1.25:8001/v1/auth`, connector name `verifier`) and omit the
    > `Path` on the rule action.

4.  Navigate to **Integration** -> **Rules**.
5.  Create a new Rule:
    *   **Name:** `gate_auth`
    *   **SQL:** `SELECT * FROM "access/+/auth"`
    *   **Action:** Select the `access_verifier` HTTP Connector created above.
    *   **Path:** `/v1/auth`
    *   **Body:** `${payload}`

> **Topic:** readers publish to `access/<id>/auth`, so the rule **must** match
> `access/+/auth`. Earlier revisions of this runbook used `door/+/tap`, which no
> component publishes — a rule on that topic silently receives nothing.
>
> **Payload:** the rule forwards the raw JSON body unchanged. The verifier
> deserializes exactly `{"reader","uid","counter","cmac"}` with
> `deny_unknown_fields`, so all four keys must be present and no extra keys may
> be added.
>
> **Deployed rule variant (verified 2026-10-11):** the production rule (name
> `verifier`) instead maps the reader from the MQTT client id —
> `SELECT clientid as reader, payload.uid as uid, payload.counter as counter,
> payload.cmac as cmac FROM "access/+/auth"` — so each device's MQTT client id
> MUST equal its device id. Verify over SSH with `emqx ctl rules list` /
> `emqx ctl rules show <id>`; trace rule execution with
> `emqx ctl trace start ruleid <id> <file>`. Note: EMQX's default ACL denies
> subscribing to exactly `#` — always test with specific topic filters.

## EMQX device onboarding

Onboard one MQTT device (door reader or card writer) by creating its broker
credential (username = device id, random 32-char password) and its topic ACL.

Broker: EMQX 6.x, REST API base `http://localhost:18083` by default — point
`EMQX_API_URL` at your deployment. Credentials are never stored in this repo.

### Option A — `emqx-device` helper (convenience)

Dry-run (default; prints a JSON plan, no broker contact; password appears
exactly once inside the plan):

```bash
cargo run --bin emqx-device -- --device-id gate-07                 # gate role
cargo run --bin emqx-device -- --device-id writer-02 --role writer  # writer role
```

Inspect the printed plan (two `POST` steps: create built-in-DB user, create
username-scoped ACL rules), then apply it:

```bash
export EMQX_API_KEY=...            # API key, or combined key:secret
export EMQX_API_SECRET=...         # optional; HTTP Basic with EMQX_API_KEY
cargo run --bin emqx-device -- --device-id gate-07 --apply
```

- Roles: `gate` (default) = `access/{id}/auth`,`presence` publish +
  `access/{id}/cmd`,`acl` subscribe; `writer`/`both` add
  `writer/{id}/job` publish + subscribe.
- Exit codes: `0` success, `1` broker request failed (nothing reported as
  applied), `2` `EMQX_API_KEY` missing.
- The generated password is printed once — record it in the device
  provisioning system, it cannot be retrieved later.
- `--api-url` / `EMQX_API_URL` overrides the broker URL; `--help` documents
  everything.

The helper is convenience only; it is not part of the verifier service. If it
is unavailable or fails, use Option B.

### Option B — manual EMQX Dashboard procedure (AUTHORITATIVE FALLBACK)

This GUI procedure is the authoritative way to onboard a device; the helper
only automates these exact steps.

1. Open the EMQX Dashboard (`https://<emqx-host>:18083`) and sign in.
2. **Authentication (credential):**
   1. Left nav: **Access Control → Authentication**.
   2. Ensure an authenticator with **Mechanism: Password-Based** and
      **Backend: Built-in Database** exists in the chain. If not: **Create** →
      select *Password-Based* + *Built-in Database* → save (defaults are fine).
   3. In the authenticator's row open **Actions → Users** (or **Built-in
      Database → User Management**).
   4. **Add User**: *User ID* = the device id (e.g. `gate-07`), *Password* =
      a generated 32-character alphanumeric password, *Is Superuser* = off.
      Confirm with **Add**.
3. **Authorization (topic ACL):**
   1. Left nav: **Access Control → Authorization**.
   2. In the **Built-in Database** backend row click **Permissions**.
   3. Add one rule per topic (Scope = **Username**, Username = the device id,
      Permission = **Allow**):

      | Action         | Topic                    | For roles      |
      | -------------- | ------------------------ | -------------- |
      | Publish        | `access/<id>/auth`       | all            |
      | Publish        | `access/<id>/presence`   | all            |
      | Subscribe      | `access/<id>/cmd`        | all            |
      | Subscribe      | `access/<id>/acl`        | all            |
      | Publish        | `writer/<id>/job`        | writer, both   |
      | Subscribe      | `writer/<id>/job`        | writer, both   |

4. **Verify:** connect with the device id as username and the recorded
   password (e.g. `mosquitto_sub -h <emqx-host> -p 8883 --cafile ca.crt -u
   '<id>' -P '<password>' -t 'access/<id>/cmd'`) and confirm a publish to
   `access/<id>/auth` succeeds while a topic outside the ACL is rejected.

Notes:

- Equivalent REST calls the helper makes (EMQX v5 API):
  `POST /api/v5/authentication/password_based%3Abuilt_in_database/users` and
  `POST /api/v5/authorization/sources/built_in_database/rules/users`.
  Re-running the REST *create* calls appends; the GUI flow is idempotent per
  user/topic (edit instead of re-adding on re-onboarding).
- API keys are managed under **Dashboard → API Key Management**; store
  `EMQX_API_KEY`/`EMQX_API_SECRET` in the environment only, never in git.

## Tag Provisioning (OTA tap-to-enroll)

A blank NTAG 424 DNA is provisioned **on the reader itself**: the admin arms a
wildcard job, a member taps their blank tag on a writer-role KeyGate node, and
the node writes the member's diversified key + SUN configuration over the air,
then reports done. No PC/SC reader, no phone app.

**Scanned NDEF URL** (firmware `ea1a182`, 2026-10-23): new keys carry
`https://keys.10bitworks.org/?uid=&c=&cmac=` — a phone tap lands on the
self-service portal (anonymous scans hit login, members land on `/me`).
Previously keys carried the dead legacy `10bitworks.org/k` path.

### MQTT contract (writer protocol)

| Topic (writer `{id}` = device id) | Direction | Payload |
| --- | --- | --- |
| `writer/{id}/job` | verifier → node | Initial arm: `{"uid":"","key":"","sun_config":{"key_version":1,"cmac_bytes":8},"job_id":"<32hex>","expires_at":"<rfc3339>"}` (wildcard) — or the same with a populated `uid`/`key` for fixed-uid jobs |
| `writer/{id}/job` | verifier → node | Claim reply for a wildcard tap: `{"uid":"<14hex>","key":"<32hex diversified>","job_id":"<32hex>","expires_at":"…"}` |
| `writer/{id}/claim` | node → verifier | `{"job_id":"<32hex>","uid":"<14hex>"}` (QoS 1) — sent when a wildcard-armed node sees a tap |
| `writer/{id}/done` | node → verifier | `{"job_id":"<32hex>","ok":true,"counter":N}` or `{"job_id":"<32hex>","ok":false,"error":"…"}` (QoS 1) |

Notes:

- Jobs are **single-use and short-lived** (TTL ≤ 120 s, server-side) and are
  never retained on the broker.
- The node also enforces its own 90 s arm window; a claim that is not answered
  within 15 s fails the job explicitly. A job whose arm window lapses without a
  tap is **not** reported — the server-side TTL lapses on its own.
- The diversified per-tag key (`AES-CMAC(master, 0x01 ‖ uid)`) is the only key
  material that ever leaves the verifier; the master key does not.

### Device roles

A node only acts on jobs when its device role is `writer` or `both`:

```bash
curl -H "Authorization: Bearer $ADMIN_BEARER_TOKEN" \
     -H 'Content-Type: application/json' \
     -d '{"role":"writer"}' \
     http://<verifier>/admin/api/devices/keygate1/role
```

### Arming via the admin UI

1. Open `/admin` (Authentik-proxied or bearer token).
2. **Provisioning (Tap-to-Enroll)** section: pick the writer device and the
   member, leave *Wildcard* checked, click **Arm writer**.
3. The panel polls every 2 s: `armed (waiting for tap)` → `tag captured
   (<uid>)` → gone (enrolled / cancelled / expired).
4. Tap the blank NTAG 424 on the writer node. The node beeps: three rising
   tones = armed, ascending triple = provisioned.
5. The tag is immediately enrolled (`tags` table, active) — a second tap now
   grants access like any provisioned tag.

Curl equivalent (uses the same admin middleware as `/v1/jobs` on the writer
API — see below):

```bash
curl -H "Authorization: Bearer $ADMIN_BEARER_TOKEN" \
     -H 'Content-Type: application/json' \
     -d '{"member_key":"<member>","device_id":"keygate1","ttl_secs":120}' \
     http://<verifier>/admin/api/jobs
```

Track/cancel:

```bash
curl -H "Authorization: Bearer $ADMIN_BEARER_TOKEN" \
     http://<verifier>/admin/api/jobs/pending?device=keygate1
curl -X DELETE -H "Authorization: Bearer $ADMIN_BEARER_TOKEN" \
     http://<verifier>/admin/api/jobs/<job_id>
```

The machine-facing `POST /v1/jobs` (bearer `ADMIN_BEARER_TOKEN`) is unchanged
and still publishes the initial arm payload itself; the admin routes wrap the
identical store/protocol operations so a proxied browser session can drive
them.

### Key-0 note

Provisioning authenticates with **factory key 0** (all zeros) and changes only
application key 1 (the SUN/CMAC key). Key 0 is never modified, so a tag can be
re-provisioned by arming a new job. The NDEF file is written while it is still
openly writable, then locked (`write = no access`, `change = key 0`) as part of
the SDM file settings.

## Key Management

### Generating a Master Key

Generate a secure 16-byte hex string:

```bash
openssl rand -hex 16
```

### Key Rotation

Update `MASTER_KEY` in the `.env` file (`main.rs` reads the env var `MASTER_KEY`)
and increment `key_version`.

## Backup and Restore

### Backup

```bash
sqlite3 data/access.db ".backup 'data/backup-$(date +%Y%m%d).db'"
```

### Restore

```bash
cp data/access.db data/access.db.bak
cp data/backup-YYYYMMDD.db data/access.db
```

## Monitoring

Register the verifier in Uptime Kuma to monitor the health endpoint: `GET /healthz`.

## Self-service portal

The access verifier includes a self-service NFC key portal (`/me`) with Authentik OIDC authentication.

### Environment variables

- `AUTHENTIK_ISSUER`: OIDC per-app Issuer URL, e.g. `https://auth.10bitworks.org/application/o/keygate-portal/` (not the domain root — domain-level discovery 404s). Since 0.3.1 the ID-token `iss` check accepts the issuer with or without a trailing slash (`from_env` trims for URL construction; Authentik's token `iss` carries the slash). Do **not** reuse `AUTHENTIK_URL` (which is the Authentik REST API base for member sync).
- `AUTHENTIK_CLIENT_ID`: Confidential OAuth2/OIDC Client ID.
- `AUTHENTIK_CLIENT_SECRET`: Confidential OAuth2/OIDC Client Secret.
- `PUBLIC_URL`: Publicly accessible base URL for the portal (e.g. `https://keys.10bitworks.org`). Redirect URI registered in Authentik must be `{PUBLIC_URL}/auth/callback`. Cookie `Secure` attribute is set when `PUBLIC_URL` begins with `https://`.
- `SESSION_SECRET`: Secret key for HMAC-SHA256 signing of the `keygate_session` JWT cookie.
- `SESSION_LIFETIME_HOURS`: Cookie session duration in hours (defaults to `12`).
- `ADMIN_ROLE`: Authentik role or group name granting access to the `/admin` dashboard (defaults to `Onboarder`).
- `SLACK_WEBHOOK_URL` (optional): Slack incoming-webhook URL. When set, a
  member-reported lost key (SUN tap page → "Report Lost Key") posts an alert
  to that channel. Unset/empty disables the notification (revocation still
  happens; a warning is logged).

If OIDC environment variables are unset, portal routes render a "not configured" notice, and `/admin` continues functioning with bearer token authentication for backwards compatibility.

### Authentik Application Requirements

1. **Client Type**: Confidential.
2. **Grant Type**: Authorization Code with PKCE (S256).
3. **Redirect URI**: `{PUBLIC_URL}/auth/callback` (e.g. `https://keys.10bitworks.org/auth/callback`).
4. **Scopes & Claims**:
   - `openid`, `profile`, `email`, **`roles`** (0.3.4+: the `roles` scope must
     be requested for the `KeyGate Roles` scope mapping to run at all).
   - `preferred_username` claim in ID token matching `members.member_key`.
   - `roles` (or `groups`) array claim in ID token. The `KeyGate Roles` scope
     mapping must use `request.user.all_roles()` (direct + group-inherited
     roles). `request.user.ak_roles` does not exist in authentik 2026.x — a
     mapping referencing it throws `AttributeError`, authentik silently omits
     the claim, and every user loses admin (check Events →
     `property_mapping_exception`).
5. **Admin Access**:
   - Users with `ADMIN_ROLE` (default `Onboarder`) in their `roles` or `groups` array can access `/admin` and `/admin/api/*` directly via browser session without needing a separate `ADMIN_BEARER_TOKEN`.
   - Logged-in non-admin sessions hitting `/admin` receive a 403 Forbidden page rather than an authentication loop.
   - Signed-out requests to `/admin` (non-API paths) redirect to `/` (0.3.6+).

### User Flow & Provisioning Policy

- **Self-service URL**: `GET /` redirects to `GET /me`.
- **Roster sync on first login** (0.3.6+): the OIDC callback runs a full
  Authentik sync cycle whenever the logging-in user has no roster row, so new
  members can provision immediately instead of waiting for the hourly sync.
  A failed sync never blocks the login (warn-level log).
- **Status Check**: Displays Authentik username, membership status (active/inactive and expiration date), current enrolled key card (UID, enrollment date, version — never raw key material), and recent door taps (last 25 for their UIDs).
- **Tap-to-Enroll Provisioning (`POST /me/provision`)**:
  - Arms a wildcard provisioning job for the member's account.
  - **TTL**: Exactly 60 seconds with countdown UI.
  - **Device Target**: Any keygate writer device (`device_id = "*"`). The job payload is published to all writer devices via MQTT, and binds to whichever device claims it on tap.
  - **Guards**: Session required; member record must exist; member must be active under standard grace period rules; at most one active pending job per member at a time (409 Conflict if pending).
  - **Replacement Semantics**: Tapping and enrolling a new key card automatically revokes any previous active tag for that member.
- **Revocation (`POST /me/revoke`)**:
  - Revokes only active cards belonging to the logged-in member.

### SUN tap landing page (0.4.0+)

Provisioned cards carry the NDEF SUN URL `https://keys.10bitworks.org/?uid=&c=&cmac=`.
Tapping a card on a phone opens that URL on `GET /`, which the portal serves
publicly (no sign-in — possession of a valid `(uid, counter, CMAC)` triple IS
the card):

- Invalid/unknown/bad-CMAC triples all get one identical "Unrecognized Key"
  page (no validity oracle).
- Valid taps render the member's display name, phone (when synced — see
  below), door status badge, tap counter (anti-replay: the counter is
  recorded exactly like a door tap, device id `web-tap`; rescanning the same
  link shows the stored counter with a "stale link" notice), enrollment date,
  and key version.
- **Open 10Bit Apps** → the Authentik application library
  (`https://auth.10bitworks.org/my/applications`).
- **Report Lost Key** (`POST /tap/report-lost`, same triple re-validated,
  replay-tolerant) revokes the tag instantly, writes
  `audit_log(reason=reported_lost)`, and posts to Slack when
  `SLACK_WEBHOOK_URL` is set.

**Member phone**: synced from Authentik user attributes
`civicrm.phone` (fallback `phone`). The "Login - sync Current Members from
CiviCRM" expression policy writes it (v2 policy: it also refreshes the
`civicrm.contact_id` anchor every login — critical after CiviCRM contact
merges, because a stale anchor pointing at a merged-away contact makes the
policy permanently remove the user from `Current Members`).

**Denial semantics** (0.4.0+): a tag whose member has no roster row is
`member_inactive` (the hourly sync removes rows when members leave the
Authentik group, which reads as a lapsed membership), not `unknown_member`.

### Production deployment (current)

- **Host**: LXC on `10.7.1.25` (ssh alias `link-docker`), path
  `/opt/access-control-verifier` — `compose.yaml` + `.env`, container
  `access-control-verifier`, port `8001:8000`, volume `verifier-data`.
- **Public URL**: `https://keys.10bitworks.org` — Nginx Proxy Manager container
  on `10.7.1.241` (proxy host id 36 → `10.7.1.25:8001`, wildcard
  `*.10bitworks.org` LE cert). Do **not** pin `extra_hosts` in compose to NPM tunnels:
  the container must reach `auth.10bitworks.org` via the public edge, or it hits
  NPM's own expired auth cert and discovery fails.
- **Release flow**: tag `vX.Y.Z` in this repo → `docker.yml` publishes
  `ghcr.io/10bitworks/access-control-verifier:X.Y.Z` → on prod swap the `image:`
  tag in `compose.yaml` → `docker compose pull && docker compose up -d` → wait
  for `(healthy)` in `docker ps`.
- **Current image**: `0.4.1` (SUN tap landing + lost-key reporting, admin
  Blueprint restyle, roster sync on first login, phone sync).

### OIDC gotchas

- **`ID token invalid: InvalidIssuer`** (fixed in 0.3.1): Authentik's ID token
  `iss` carries the per-app path **with trailing slash**; the validator now
  accepts both forms. Before 0.3.1 any env-vs-token slash mismatch failed at
  callback.
- **Provider grant types**: the Authentik provider must include
  `authorization_code` (+ `refresh_token`); an empty `grant_types` list makes
  authorize reject with "request is otherwise malformed".
- **Password login**: members authenticate via passkey/Slack/Gmail in the
  default flow; password login only exists in the `admin-login` flow
  (policy-gated). For E2E testing, use a test user in `authentik Admins` +
  `admin-login` flow, then remove the membership.

## Relocation Checklist

The service is fully containerized. Moving to a new location requires:

1.  Deploying the `compose.yaml` stack.
2.  Updating the MQTT broker DNS/IP in the environment.
3.  Re-establishing Tailscale/LAN connectivity.

## v2 Offline-First Reader Operations (0.5.0+)

> **MONITOR PAUSE REMINDER**: Before performing any gateway or reader restarts,
> firmware OTA updates, or broker ACL updates, pause the relevant monitors at
> `https://uptime.10bitworks.com/metrics` (using API Key `uk1_pfrCn5jYgx6KryDGOqFWmIcEaKFGDhzZC6XdAZKM`,
> HTTP Basic Auth with empty username) to prevent false alerts.

### 1. Reader Commissioning Procedure (D3)

Offline verification requires the door reader to hold the active master key in
its dedicated flash partition (`keygate`). In v2, key material never crosses
MQTT during routine taps.

1. **Gate eligibility**:
   Ensure the reader exists in `devices` with `offline_verify = 1`. In the admin UI
   (`/admin`) or via API:
   ```bash
   curl -X POST -H "Authorization: Bearer $ADMIN_BEARER_TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"device_id":"keygate-frontdoor","role":"both","offline_verify":true}' \
     http://localhost:8000/admin/api/devices
   ```
2. **Initial Hello & Commissioning trigger**:
   When the uncommissioned reader boots, it publishes `keygate/v2/{id}/hello` with
   an empty `key_versions` array.
3. **Verifier Commissioning Dispatch**:
   The verifier automatically publishes the active master key version to
   `keygate/v2/{id}/commission`:
   ```json
   {"key_version": 1, "master_hex": "..."}
   ```
   *Note: This topic is ACL-locked to the verifier principal and target device clientid,
   and is published non-retained.*
4. **Verification**:
   The reader persists the key in flash and echoes `key_versions: [1]` in its next hello.
   Check `/admin` Devices table or verifier logs to confirm handshake completion.

### 2. Fleet Master Key Rotation Window (D3)

Master key rotation invalidates every physical card's diversified key and requires
a coordinated maintenance window.

1. **Pause monitors**:
   Pause door reader and access verifier monitors in Uptime Kuma.
2. **Stage dual-master support**:
   Devices support caching two master keys `{current, previous}`:
   - Configure the new master key `vN+1` on the verifier.
   - The verifier distributes `vN+1` via `keygate/v2/{id}/commission` to all
     `offline_verify = 1` readers.
   - **Gate**: Require a hello echo acknowledging `vN+1` from every reader before proceeding.
3. **Re-provision cards**:
   Re-enroll member cards at `vN+1` using the card writer and admin portal. Readers
   verify CMAC against the tag's key_version, falling back to previous version if needed.
4. **Retire previous master**:
   Once all tags are re-enrolled, decommission `vN` in the verifier.
5. **Resume monitors**:
   Unpause Uptime Kuma monitors and verify normal tap entries in the Audit Log and Tap Reports.

### 3. Retained-ACL Purge Procedure (S6)

Legacy verifier versions published retained ACL payloads to `access/{id}/acl`. In v2,
per-tag key material is never broadcast. Stale retained ACLs must be purged from the broker.

```bash
# Publish empty retained messages with QoS 1 to clear broker state
mosquitto_pub -h $MQTT_HOST -p $MQTT_PORT -u $MQTT_USERNAME -P $MQTT_PASSWORD \
  -t "access/keygate1/acl" -r -n -q 1

mosquitto_pub -h $MQTT_HOST -p $MQTT_PORT -u $MQTT_USERNAME -P $MQTT_PASSWORD \
  -t "access/keygate-frontdoor/acl" -r -n -q 1

# Purge legacy presence retained topic if cleaning up retired reader
mosquitto_pub -h $MQTT_HOST -p $MQTT_PORT -u $MQTT_USERNAME -P $MQTT_PASSWORD \
  -t "access/keygate1/presence" -r -n -q 1
```

Verify via subscriber that retained messages are gone:
```bash
mosquitto_sub -h $MQTT_HOST -p $MQTT_PORT -u $MQTT_USERNAME -P $MQTT_PASSWORD \
  -t "access/+/acl" --retained-only -W 3
```

### 4. Device Rename Procedure (e.g. `keygate1` → `keygate-frontdoor`) (D9)

Renaming a physical door reader must follow strict sequencing to avoid locking the door
or causing an identity split:

1. **Pause monitors**:
   Pause door uptime checks (`keygate1` / `keygate-frontdoor`) on Uptime Kuma.
2. **Pre-populate Devices table BEFORE firmware update**:
   The verifier role gate requires the device to be registered before authorization:
   ```bash
   curl -X POST -H "Authorization: Bearer $ADMIN_BEARER_TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"device_id":"keygate-frontdoor","role":"both","offline_verify":false}' \
     http://localhost:8000/admin/api/devices
   ```
3. **Configure EMQX credentials & ACLs**:
   Provision broker credentials and topic permissions for the new `clientid`:
   ```bash
   cargo run --bin emqx-device -- --device-id keygate-frontdoor --apply
   ```
4. **Build & Deploy Firmware**:
   Build firmware with `DEVICE_ID=keygate-frontdoor`. Use `ota-push.py --prod` to deploy
   to the production reader under probation.
5. **Verify Presence & Taps**:
   Observe hello and presence on `keygate/v2/keygate-frontdoor/hello` and `access/keygate-frontdoor/presence`.
   Perform a physical test tap and verify audit row in `/admin`.
6. **Purge legacy retained state**:
   Execute the Retained-ACL Purge procedure for the old `keygate1` topic tree.
7. **Resume monitors & update configs**:
   Update monitor labels in Uptime Kuma, wiki network tables, and unpause monitors. Keep
   the legacy `keygate1` row in `devices` for historical audit integrity.
