-- AAPM Database Schema for TimescaleDB

-- Enable TimescaleDB extension
CREATE EXTENSION IF NOT EXISTS timescaledb;

-- Agents table
CREATE TABLE agents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id VARCHAR(255) NOT NULL,
    name VARCHAR(255),
    framework VARCHAR(50) NOT NULL,
    assistant_id VARCHAR(255),  -- OpenAI assistant ID or similar
    environment_id VARCHAR(255),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(org_id, assistant_id, framework)
);

CREATE INDEX idx_agents_org ON agents(org_id);
CREATE INDEX idx_agents_assistant_id ON agents(assistant_id);

-- Agent events hypertable
CREATE TABLE agent_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id VARCHAR(255) NOT NULL,
    agent_id UUID REFERENCES agents(id) ON DELETE CASCADE,
    event_type VARCHAR(50) NOT NULL,
    ts TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    metadata_json JSONB,
    payload_hash VARCHAR(64),  -- SHA-256 hash of payload (without sensitive fields)
    event_hash VARCHAR(64) NOT NULL,  -- SHA-256 hash of canonicalized event
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Convert to hypertable (partitioned by time)
SELECT create_hypertable('agent_events', 'ts');

CREATE INDEX idx_agent_events_org_ts ON agent_events(org_id, ts DESC);
CREATE INDEX idx_agent_events_agent_ts ON agent_events(agent_id, ts DESC);
CREATE INDEX idx_agent_events_type ON agent_events(event_type);
CREATE INDEX idx_agent_events_hash ON agent_events(event_hash);

-- Event chain hypertable (for cryptographic integrity)
CREATE TABLE event_chain (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id VARCHAR(255) NOT NULL,
    agent_id UUID REFERENCES agents(id) ON DELETE CASCADE,
    seq_no BIGSERIAL NOT NULL,
    event_id UUID REFERENCES agent_events(id) ON DELETE CASCADE,
    event_hash VARCHAR(64) NOT NULL,
    prev_chain_hash VARCHAR(64) NOT NULL,  -- Previous event's chain_hash (or '0'*64 for genesis)
    chain_hash VARCHAR(64) NOT NULL,  -- SHA-256(event_hash + prev_chain_hash)
    ts TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(org_id, agent_id, seq_no),
    UNIQUE(org_id, agent_id, chain_hash)
);

-- Convert to hypertable
SELECT create_hypertable('event_chain', 'ts');

CREATE INDEX idx_event_chain_org_agent_seq ON event_chain(org_id, agent_id, seq_no);
CREATE INDEX idx_event_chain_hash ON event_chain(chain_hash);
CREATE INDEX idx_event_chain_prev_hash ON event_chain(prev_chain_hash);

-- Chain signatures table (signed batch roots)
CREATE TABLE chain_signatures (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id VARCHAR(255) NOT NULL,
    agent_id UUID REFERENCES agents(id) ON DELETE CASCADE,
    key_id VARCHAR(255) NOT NULL,
    batch_root_hash VARCHAR(64) NOT NULL,  -- Root hash of a batch of chain hashes
    signature TEXT NOT NULL,  -- Ed25519 signature (hex-encoded)
    seq_start BIGINT NOT NULL,
    seq_end BIGINT NOT NULL,
    signed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_chain_signatures_org_agent ON chain_signatures(org_id, agent_id);
CREATE INDEX idx_chain_signatures_key_id ON chain_signatures(key_id);
CREATE INDEX idx_chain_signatures_signed_at ON chain_signatures(signed_at);

-- API keys table (simple auth for MVP)
CREATE TABLE api_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id VARCHAR(255) NOT NULL UNIQUE,
    api_key_hash VARCHAR(64) NOT NULL,  -- SHA-256 hash of API key
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at TIMESTAMPTZ
);

CREATE INDEX idx_api_keys_org ON api_keys(org_id);
CREATE INDEX idx_api_keys_hash ON api_keys(api_key_hash);

