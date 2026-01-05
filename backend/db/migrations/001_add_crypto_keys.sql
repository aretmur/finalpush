-- Migration: Add crypto_keys table for key rotation support
-- Version: 001
-- Date: 2026-01-06

-- Crypto keys table for Ed25519 key management
CREATE TABLE IF NOT EXISTS crypto_keys (
    id VARCHAR(255) PRIMARY KEY,
    org_id VARCHAR(255) NOT NULL,
    key_type VARCHAR(50) NOT NULL DEFAULT 'signing',
    public_key TEXT NOT NULL,
    private_key_encrypted TEXT NOT NULL,  -- Encrypted with master key
    algorithm VARCHAR(50) NOT NULL DEFAULT 'Ed25519',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    active BOOLEAN NOT NULL DEFAULT TRUE,
    
    CONSTRAINT fk_crypto_keys_org FOREIGN KEY (org_id) 
        REFERENCES api_keys(org_id) ON DELETE CASCADE
);

CREATE INDEX idx_crypto_keys_org ON crypto_keys(org_id);
CREATE INDEX idx_crypto_keys_active ON crypto_keys(org_id, active) WHERE active = TRUE;

-- Add key_id column to chain_signatures if not exists
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'chain_signatures' AND column_name = 'key_id'
    ) THEN
        ALTER TABLE chain_signatures 
        ADD COLUMN key_id VARCHAR(255) REFERENCES crypto_keys(id);
    END IF;
END $$;

-- Create index on key_id
CREATE INDEX IF NOT EXISTS idx_chain_signatures_key_id ON chain_signatures(key_id);

-- Add comment explaining the table
COMMENT ON TABLE crypto_keys IS 'Stores Ed25519 key pairs for signing chain batches. Private keys are encrypted at rest.';
COMMENT ON COLUMN crypto_keys.private_key_encrypted IS 'PEM-encoded private key encrypted with Fernet using master key from KMS';
COMMENT ON COLUMN crypto_keys.active IS 'Only one key per org should be active at a time. Old keys retained for signature verification.';
