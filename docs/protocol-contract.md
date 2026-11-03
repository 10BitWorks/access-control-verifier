# Protocol Wire Contract: KeyGate Firmware & Access Control Verifier

This document defines the normative MQTT wire interaction contracts between the reader firmware (`keygate-esp-access-devices`) and the backend verifier (`access-control-verifier`).

Both v2 offline-first and legacy shadow topics are detailed below with publisher, subscriber, ack requirements, and failure modes when violated.

---

## 1. Wire Contract Matrix

| Topic Pattern | Publisher | Subscriber | QoS | Payload Format | Ack Semantics | Failure Mode if Violated |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `keygate/v2/{id}/report` | Device (Firmware) | Verifier | QoS 1 | JSON (`V2TapPayload`) | **Mandatory QoS 1 Ack** published by verifier to `keygate/v2/{id}/ack` with `tap_id`, `entry: null`, `counter_floor: 0`, and `time_s: <epoch>`. | **Outbox Poison Loop (2026-11-02 deadlock)**: Device flushes head record (`rec.tap_seq`) every 100 ms and advances WAL head cursor ONLY on ack. If verifier does not ack, device replays head record indefinitely (~5-10 Hz), starving all newer queued WAL records and causing outbox depth to grow without bound. |
| `keygate/v2/{id}/tap` | Device (Firmware) | Verifier | QoS 1 | JSON (`V2TapPayload` with `decision: null`, `reason: null`) | **Mandatory QoS 1 Ack** published by verifier to `keygate/v2/{id}/ack` within 500 ms with `tap_id`, `entry` (or null if invalid/unknown), max-merged `counter_floor`, and `time_s`. | **Consult Timeout & Fallback**: If ack does not arrive within 500 ms, firmware falls back to cached local decision from roster snapshot in authoritative mode. In shadow mode, tag actuation depends on legacy `access/{id}/cmd`. |
| `keygate/v2/{id}/ack` | Verifier | Device (Firmware) | QoS 1 | JSON (`V2AckPayload`: `tap_id`, `entry`, `counter_floor`, `time_s`) | None (Terminal ack packet). Handled by device: updates `TimeAnchor`, resolves pending consult slot, advances outbox WAL head cursor. | **Stale Horizon / Time Drift**: If device drops or fails to parse ack, WAL record remains unacked (re-flushed later) and `time_uncertain` remains true (preventing local expiry validation). |
| `keygate/v2/{id}/hello` | Device (Firmware) | Verifier | QoS 1 | JSON (`V2HelloPayload`: `roster_gen`, `key_versions`, `outbox_depth`, `time_uncertain`, `git_sha`) | None directly to ack topic. Verifier responds by inspecting state and dispatching sync chunks, authoritative flip, and/or commissioning. | **Fleet Desynchronization**: If unhandled, reader cannot synchronize roster deltas, cannot receive updated master keys, and remains in uncommissioned / shadow mode. |
| `keygate/v2/{id}/sync` | Verifier | Device (Firmware) | QoS 1 | Binary Chunks (`0x4B47` magic, 20B entries, CRC-32) OR JSON (`{"authoritative": true}`) | None (TCP QoS 1 puback only). Device `SyncAssembler` buffers chunks up to 30 s and validates CRC before atomic flash flip. | **Roster Stalling / Gap**: If chunks arrive out of order, assembler discards sequence after 30 s timeout. If authoritative flip is never sent, device remains in shadow mode. |
| `keygate/v2/{id}/commission` | Verifier | Device (Firmware) | QoS 1 | JSON (`{"key_version": N, "master_hex": "..."}`) | None (TCP QoS 1 puback only). Device shifts `masters[0]` to `masters[1]` and writes new key as `masters[0]`. | **Uncommissioned Lockout**: Without active master keys, reader cannot authenticate NTAG 424 DNA SUN CMAC locally and denies access or falls back to legacy online auth. |
| `keygate/v2/{id}/diag` | Device (Firmware) | Verifier / Ops | QoS 0 | Line-rate text / JSON log messages | None (Best-effort stream). | Loss of runtime debug visibility; non-fatal to access control. |
| `keygate/v2/{id}/diag/drain` | Verifier / Ops | Device (Firmware) | QoS 0 | Trigger payload | Triggers device to dump up to recent ring-buffer diagnostic lines to `keygate/v2/{id}/diag`. | Diagnostics snapshot cannot be retrieved on demand. |
| `access/{id}/ota/meta` | Host (`ota-push.py`) | Device (Firmware) | QoS 1 | JSON (`{"size": N, "sha256": "...", "version": "..."}`) | Device publishes status to `access/{id}/ota/status`. | Firmware update fails to initiate. |
| `access/{id}/ota/data` | Host (`ota-push.py`) | Device (Firmware) | QoS 1 | Binary chunk (offset-prefixed) | Device classifies offset (`classify_offset`): matches written -> accept; < written -> duplicate; > written -> **hold position** (publish `awaiting {written}` to status). | **OTA Abort / Flap Wedge**: If device treated a gap as fatal abort instead of hold, any dropped QoS 1 chunk would abort the entire update. If host does not rewind upon `awaiting`, stream deadlocks. |
| `access/{id}/ota/end` | Host (`ota-push.py`) | Device (Firmware) | QoS 1 | JSON (`{"sha256": "..."}`) | Device checks whole-image SHA-256 and flips otadata marker before rebooting. | Rollback to previous firmware slot upon failure. |
| `access/{id}/auth` | Device (Firmware) | Verifier | QoS 1 | JSON (Legacy auth request: UID, counter, SUN CMAC) | Verifier publishes grant or deny cmd to `access/{id}/cmd`. | **Legacy Actuation Failure**: In shadow mode, reader relies on `access/{id}/cmd` to pulse the door relay. If verifier does not respond, door remains locked. |
| `access/{id}/cmd` | Verifier | Device (Firmware) | QoS 1 | JSON (`{"grant": bool, "pulse_ms": u32, "reason": str}`) | None (Device actuates relay). | Door fails to open for legacy auth or admin one-shot overrides. |
| `access/{id}/presence` | Device (Firmware) | Verifier | QoS 1 (Retained) | Plaintext (`online` / `offline` via LWT) | None. | Verifier treats device as offline or online incorrectly. |
| `access/{id}/acl` | Verifier | Retired / Purged | QoS 1 (Retained) | JSON (Legacy per-tag keys bundle) | **DEPRECATED & RETIRED (0.5.2)**: Must NEVER be published. | Per-tag key leakage across MQTT network. |

---

## 2. Normative Protocols & State Machines

### 2.1 Outbox WAL Flush & Ack Loop (D4 / A19)
- **Firmware Rule (`node.rs:1683-1739`)**:
  - Outbox holds write-ahead records of tap events.
  - While connected and not in OTA, every 100 ms the firmware reads head record `rec = store.get_record(0)`.
  - Publishes `keygate/v2/{id}/report` with `tap_id = "{device_id}:{rec.tap_seq}"`.
  - **Invariant**: The head cursor advances (`store.ack_up_to(seq)`) **strictly upon receiving** an ack with matching `tap_id` on `keygate/v2/{id}/ack`.
- **Verifier Rule (`mqtt.rs:816-907`)**:
  - `process_v2_tap_or_report` handles both `V2Event::Tap` and `V2Event::Report`.
  - For `V2Event::Report`: Ingests report into `tap_reports` table (idempotent; duplicates safely ignored).
  - **Invariant**: MUST ALWAYS return `Some(TapProcessResult { entry: None, counter_floor: 0 })` so an ack is published to `keygate/v2/{id}/ack`.
  - Even if ingest fails, an anomaly (`report_rejected`) is recorded and an ack is published to unblock the head record from creating a poison loop.

### 2.2 Consult Tap & TimeAnchor Update (D2 / R12 / A15)
- **Firmware Rule (`node.rs:520-619`)**:
  - When a tag is presented, firmware computes local decision and publishes consult to `keygate/v2/{id}/tap` with `decision: null`.
  - Awaits correlated ack on `keygate/v2/{id}/ack` for up to 500 ms.
  - On ack:
    1. Extracts `time_s`. If `time_s > 0`, invokes `TIME_ANCHOR.update(time_s, uptime_ms)` and clears `time_uncertain`.
    2. Derives verifier decision from `ack.entry` and active policy.
    3. In authoritative mode: actuates relay on verifier grant. In shadow mode: logs divergence between local decision and verifier decision.
    4. Publishes final outcome to `keygate/v2/{id}/report`.
  - On timeout: Falls back to cached local decision from roster in authoritative mode.

### 2.3 OTA Gap-Hold vs Abort (OTA Resilience)
- **Firmware Rule (`ota_probation.rs:82-92`)**:
  - Evaluates `classify_offset(chunk_offset, bytes_written, is_erasing)`:
    - `chunk_offset == bytes_written`: Accept chunk and write to flash.
    - `chunk_offset < bytes_written`: Duplicate chunk (already written), silently ignore.
    - `chunk_offset > bytes_written`: **Hold position** (gap detected). Do NOT abort the transfer! Publish `awaiting {bytes_written}` on `access/{id}/ota/status`.
- **Host Script Rule (`scripts/ota-push.py`)**:
  - Listens to `access/{id}/ota/status`. If an `awaiting {offset}` message arrives, rewinds file pointer to `{offset}` and resumes transmission.
