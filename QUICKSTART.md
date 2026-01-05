# AAPM MVP Quick Start Guide

## Prerequisites

- Docker and Docker Compose
- Python 3.11+
- Node.js 18+ (for dashboard)
- OpenAI API key (for testing SDK)

## Step 1: Start Infrastructure

```bash
cd infra
docker-compose up -d
```

Wait for services to start (30-60 seconds). Verify:

```bash
# Check services
docker-compose ps

# Check Kafka
docker-compose logs kafka | tail -20

# Check TimescaleDB
docker-compose exec timescaledb psql -U aapm -d aapm -c "SELECT version();"
```

## Step 2: Create API Key

```bash
# Connect to database
docker-compose exec timescaledb psql -U aapm -d aapm

# Create API key (replace 'test-org' and 'test-key-123' with your values)
INSERT INTO api_keys (org_id, api_key_hash)
VALUES (
  'test-org',
  encode(digest('test-key-123', 'sha256'), 'hex')
);
```

## Step 3: Generate Signing Key (Optional)

```bash
# Generate Ed25519 key pair
openssl genpkey -algorithm Ed25519 -out signing_key.pem
openssl pkey -in signing_key.pem -pubout -out signing_key.pub

# Export for docker-compose
export AAPM_SIGNING_KEY=$(cat signing_key.pem)
export AAPM_KEY_ID="aapm-key-v1"
```

Then update `infra/docker-compose.yml` to include these env vars, or restart services:

```bash
cd infra
AAPM_SIGNING_KEY=$(cat ../signing_key.pem) AAPM_KEY_ID="aapm-key-v1" docker-compose up -d
```

## Step 4: Install and Test SDK

```bash
cd sdk/python
pip install -e .

# Set environment variables
export OPENAI_API_KEY="sk-your-key-here"
export AAPM_API_KEY="test-key-123"
export AAPM_ENDPOINT="http://localhost:8000"
export AAPM_ORG_ID="test-org"

# Run example
python examples/basic_example.py
```

## Step 5: Start Dashboard

```bash
cd dashboard
npm install
npm run dev
```

Visit http://localhost:3000

Login with:
- API Key: `test-key-123`
- Organization ID: `test-org`
- Endpoint: `http://localhost:8000`

## Step 6: Verify Events

### Via API

```bash
# List agents
curl -H "X-API-Key: test-key-123" \
  http://localhost:8000/v1/agents

# Get events for an agent
curl -H "X-API-Key: test-key-123" \
  "http://localhost:8000/v1/agents/{agent_id}/events"

# Verify chain
curl -H "X-API-Key: test-key-123" \
  "http://localhost:8000/v1/verify/chain?agent_id={agent_id}"
```

### Via Dashboard

1. Login at http://localhost:3000
2. View agents list
3. Click on an agent to see events
4. Click "Verify Chain" to check integrity

## Troubleshooting

### Kafka not starting

```bash
# Check logs
docker-compose logs kafka

# Restart
docker-compose restart kafka
```

### Database connection errors

```bash
# Check if TimescaleDB is ready
docker-compose exec timescaledb pg_isready -U aapm

# Check database exists
docker-compose exec timescaledb psql -U aapm -d aapm -c "\dt"
```

### Worker not processing events

```bash
# Check worker logs
docker-compose logs worker

# Check Kafka topic
docker-compose exec kafka kafka-console-consumer \
  --bootstrap-server localhost:9092 \
  --topic agent-events \
  --from-beginning
```

### SDK not sending events

- Check `AAPM_DISABLED` is not set to "true"
- Check `AAPM_ENDPOINT` is correct
- Check API key is valid
- Check backend is running: `curl http://localhost:8000/`

## Next Steps

1. **Read Documentation**:
   - `docs/SECURITY.md` - Security model
   - `docs/INTEGRITY_SPEC.md` - Cryptographic integrity spec

2. **Run Tests**:
   ```bash
   cd backend
   pip install -r requirements.txt
   pip install -r tests/requirements.txt
   pytest tests/
   ```

3. **Customize**:
   - Update signing key rotation policy
   - Configure retention policies
   - Add more event types
   - Extend SDK for other frameworks

## Production Considerations

- Use KMS for signing keys (not environment variables)
- Enable TLS/HTTPS
- Set up monitoring and alerting
- Configure backup and retention policies
- Implement rate limiting
- Add SSO/RBAC

