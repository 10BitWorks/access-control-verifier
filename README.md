# access-control-verifier

NTAG424 DNA Door Access Verifier for 10BitWorks Makerspace.

## System Architecture

```mermaid
flowchart TD
    Card[NTAG424 DNA] -->|Tap| Reader[OSDP Door Reader]
    Reader -->|MQTT Publish| EMQX[EMQX Broker]
    EMQX -->|Webhook| Verifier[access-control-verifier]
    
    subgraph access-control-verifier
        Auth[/v1/auth] --> MAC[SUN CMAC Verification]
        MAC --> Cache[(SQLite Offline Cache)]
        Sync[Authentik Sync Worker] <--> Cache
    end
    
    Verifier -->|MQTT Publish| DoorRelay[Door Relay Controller]
    Verifier -->|API| Authentik[Authentik IdP]
```

## Threat Model

*   **Anti-clone:** SUN CMAC over dynamic counter and card UID. Every tap generates a unique cryptographic signature.
*   **Anti-replay:** Strictly monotonic tap counter. The verifier rejects counters lower than or equal to the last seen counter for a given UID.
*   **Accepted Risk:** Door readers store diversified keys locally for offline fail-safe operation. If a reader is physically extracted and disassembled, only that reader's sub-keys are exposed, not the master key.

## Quickstart

### Environment Setup

Create a `.env` file (see `.env.example`):

```env
DATABASE_URL=sqlite://data/access.db
MASTER_KEY_HEX=...
MQTT_BROKER_URL=mqtt://...
AUTHENTIK_API_TOKEN=...
```

### Running via Docker Compose

```bash
docker compose up -d
```

### Building from Source

```bash
cargo build --release
```