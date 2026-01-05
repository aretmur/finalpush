# AAPM MVP - Agent Activity & Permission Monitor

Tamper-evident, cryptographically verifiable audit trails for AI agents.

## Architecture

- **Backend**: FastAPI for ingestion and query APIs
- **Worker**: Kafka consumer that processes events and computes cryptographic chains
- **Database**: TimescaleDB (PostgreSQL + hypertables)
- **SDK**: Python wrapper for OpenAI SDK
- **Dashboard**: Next.js web UI

## Quick Start

### 1. Start Infrastructure

```bash
cd infra
docker-compose up -d
```

This starts:
- Zookeeper + Kafka
- TimescaleDB
- Backend API (port 8000)
- Worker

### 2. Create API Key

```bash
# Connect to database
psql postgresql://aapm:aapm_dev_password@localhost:5432/aapm

# Create API key (replace with your org_id and key)
INSERT INTO api_keys (org_id, api_key_hash)
VALUES ('test-org', encode(digest('test-key-123', 'sha256'), 'hex'));
```

### 3. Generate Signing Key (Optional)

```bash
# Generate Ed25519 key pair
openssl genpkey -algorithm Ed25519 -out signing_key.pem
openssl pkey -in signing_key.pem -pubout -out signing_key.pub

# Set environment variable
export AAPM_SIGNING_KEY=$(cat signing_key.pem)
export AAPM_KEY_ID="aapm-key-v1"
```

### 4. Install SDK

```bash
cd sdk/python
pip install -e .
```

### 5. Run Example

```bash
export OPENAI_API_KEY="sk-..."
export AAPM_API_KEY="test-key-123"
export AAPM_ENDPOINT="http://localhost:8000"
export AAPM_ORG_ID="test-org"

python examples/basic_example.py
```

### 6. Start Dashboard

```bash
cd dashboard
npm install
npm run dev
```

Visit http://localhost:3000

## API Endpoints

- `POST /v1/events` - Ingest events (from SDK)
- `GET /v1/agents` - List agents
- `GET /v1/agents/{id}/events` - Get agent events
- `GET /v1/agents/{id}/summary` - Get agent summary
- `GET /v1/verify/chain?agent_id={id}` - Verify chain integrity

## Cryptographic Integrity

- **Event Hashing**: SHA-256 hash of canonicalized event payload
- **Hash Chaining**: Each event's chain_hash = SHA-256(event_hash + prev_chain_hash)
- **Digital Signatures**: Ed25519 signatures on batch root hashes
- **Tamper Detection**: Any modification breaks the chain (detectable)

## Development

### Backend

```bash
cd backend
pip install -r requirements.txt
uvicorn backend.app.main:app --reload
```

### Worker

```bash
cd backend
python -m backend.worker.main
```

## Testing

See `backend/tests/` for unit and integration tests.

## Documentation

- `docs/SECURITY.md` - Threat model and security considerations
- `docs/INTEGRITY_SPEC.md` - Cryptographic integrity specification

