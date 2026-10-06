# Operations Runbook

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
