# Legacy Door Auth Business Rules (door1)

This document captures the business rules from the legacy Django-based `door1` member authentication system (running at 10.7.1.244, LXC 204), primarily as implemented in `cobalt/my_door_auth.py` and `frontdoor/access_10Bit.py`.

## Architecture Summary
The legacy system operates as a cached proxy. The RFID reader reads a ROT13-obfuscated email from a card and sends it to the Django server. If the member is not in the local cache or access is denied, the reader triggers a cache update (`/membership/update`) which pulls recent orders from the Squarespace API, then retries. The admin UI exposes `MemberStatus` and `DateOfLastPayment` fields to determine door access.

## Status Mapping Table

| Legacy Status / Field | Legacy Effect on Door | Proposed Mapping (overrides / cache) | Notes |
| :--- | :--- | :--- | :--- |
| `MemberStatus: TempBan` | Deny | `overrides` table (`kind=ban`, `expires_at=...`) | Overrides any payment date (`my_door_auth.py:86`) |
| `MemberStatus: PermaBan` | Deny | `overrides` table (`kind=ban`, `expires_at=null`) | Handled identically to TempBan in legacy code |
| `MemberStatus: Sponsored` | Grant | `overrides` table (`kind=allow`) | Skips `DateOfLastPayment` check entirely |
| `MemberStatus: GoodStanding` | Fallthrough | Implicit via `members-cache` active sync | Checked implicitly if not Ban/Sponsored |
| `MemberStatus: New` | Fallthrough | Implicit | Checked implicitly if not Ban/Sponsored |
| `DateOfLastPayment` | Grant if < 35 days | `members-cache` (Authentik active group) | Primary time-based check (`my_door_auth.py:96`) |

## Window Rules
- **Cardmaker Kiosk (33 days):** Only creates cards if the Squarespace API returns an order within the last 33 days.
- **Door Controllers (35 days):** `PAYMENT_WINDOW = 35`. Grants access if `DateOfLastPayment` is within 35 days (effectively a 4-5 day grace period beyond the standard monthly subscription).
- **Grace Behavior:** If a member pays on day 30, but squarespace syncing lags, the cache update request attempts to fetch their latest payment to authorize access.

## New System Differences
- **SUN Tags:** Replaces ROT13 obfuscation with cryptographically secure NFC tags (SUN) verified via AES keys.
- **Authentik Groups:** Replaces Squarespace order polling with direct Authentik group membership validation.
- **Unified Policy:** Moves access logic from the Pi clients (cobalt/frontdoor) to a centralized Rust verifier API.
- **Standardized Grace:** Implements configurable `GRACE_DAYS=5` / `LOCKOUT_DAYS=10` natively instead of hardcoded 35-day deltas.
- **Decoupled Admin UI:** Relies on a standalone `overrides` table (Postgres) rather than a monolithic Django admin portal.
