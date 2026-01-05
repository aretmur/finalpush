# Cryptographic Integrity Specification

## Overview

AAPM provides tamper-evident, cryptographically verifiable audit trails using:
1. **SHA-256 Hashing**: Event fingerprints
2. **Hash Chaining**: Append-only log structure
3. **Digital Signatures**: Ed25519 signatures on batch roots

## Event Hashing

### Canonical JSON

Events are converted to canonical JSON before hashing:
- Sorted keys (alphabetical)
- No whitespace
- Deterministic encoding (UTF-8)

Example:
```json
{"a":1,"b":2,"c":3}
```

### Event Hash Computation

```python
event_hash = SHA-256(canonical_json(safe_payload))
```

Where `safe_payload` excludes sensitive fields:
- `user_query` → replaced with `user_query_hash`
- Raw data content → replaced with identifiers only

### Event Payload Structure

```json
{
  "agent_id": "agent_123",
  "event_type": "tool_call",
  "timestamp": "2025-01-01T00:00:00Z",
  "tool_name": "code_interpreter",
  "data_sources": [
    {"type": "file", "identifier": "file_xyz"}
  ],
  "user_query_hash": "abc123...",  // SHA-256 hash, not plaintext
  "user_query_token_count": 50,
  "metadata": {...}
}
```

## Hash Chaining

### Chain Hash Computation

Each event's chain hash depends on the previous event:

```
chain_hash_n = SHA-256(event_hash_n + chain_hash_(n-1))
```

Where:
- `chain_hash_0 = "0" * 64` (genesis hash)
- `event_hash_n` is the SHA-256 hash of event n
- `chain_hash_(n-1)` is the previous event's chain hash

### Chain Structure

```
Event 1: event_hash_1 → chain_hash_1 = SHA-256(event_hash_1 + "0"*64)
Event 2: event_hash_2 → chain_hash_2 = SHA-256(event_hash_2 + chain_hash_1)
Event 3: event_hash_3 → chain_hash_3 = SHA-256(event_hash_3 + chain_hash_2)
...
```

### Tamper Detection

If any event is modified:
1. Its `event_hash` changes
2. Its `chain_hash` changes
3. All subsequent `chain_hash` values become invalid
4. Chain verification detects the break

## Digital Signatures

### Batch Root Hash

Periodically (every N events or time interval), compute a batch root:

```
batch_root_hash = SHA-256(chain_hash_1 + chain_hash_2 + ... + chain_hash_N)
```

### Signature

Sign the batch root hash with Ed25519:

```
signature = Ed25519_Sign(batch_root_hash, private_key)
```

### Signature Storage

```json
{
  "key_id": "aapm-key-v1",
  "algorithm": "Ed25519",
  "batch_root_hash": "abc123...",
  "signature": "def456...",  // hex-encoded
  "seq_start": 1,
  "seq_end": 100,
  "signed_at": "2025-01-01T00:00:00Z"
}
```

## Verification

### Chain Verification

To verify chain integrity:

1. Fetch chain entries ordered by `seq_no`
2. For each entry:
   - Compute expected `chain_hash = SHA-256(event_hash + prev_chain_hash)`
   - Compare with stored `chain_hash`
   - If mismatch → chain broken at this sequence number
3. Return verification result

### Signature Verification

To verify signatures:

1. Fetch signatures for time range
2. For each signature:
   - Recompute `batch_root_hash` from chain hashes in range
   - Verify signature using public key (lookup by `key_id`)
   - If invalid → signature verification fails
3. Return verification result

## Example

### Event Flow

```
1. SDK emits event → Ingestion API
2. Ingestion API → Kafka
3. Worker consumes from Kafka
4. Worker computes:
   - event_hash = SHA-256(canonical_json(event))
   - prev_chain_hash = get_last_chain_hash(agent_id)
   - chain_hash = SHA-256(event_hash + prev_chain_hash)
5. Worker stores:
   - agent_events (with event_hash)
   - event_chain (with chain_hash)
6. Periodically, worker signs batch root
```

### Verification Flow

```
1. Client calls GET /v1/verify/chain?agent_id=...
2. Backend fetches chain entries
3. Backend verifies each link:
   - computed = SHA-256(event_hash + prev_chain_hash)
   - stored = chain_hash from database
   - if computed != stored → tampered
4. Backend checks signatures
5. Backend returns verification result
```

## Properties

### Integrity

- **Immutable**: Events cannot be modified without detection
- **Append-only**: New events can only be added, not inserted
- **Tamper-evident**: Any modification breaks the chain

### Attribution

- **Provenance**: Signatures prove events originated from AAPM system
- **Non-repudiation**: Cannot deny creating signed events
- **Timestamping**: Signed_at provides temporal proof

### Auditability

- **Independent Verification**: Anyone can verify without AAPM system
- **Public Key Distribution**: Public keys can be shared for verification
- **Export Capability**: Events + hashes + signatures can be exported

## Implementation Details

### Database Schema

```sql
-- Event chain table
CREATE TABLE event_chain (
    seq_no BIGSERIAL,
    event_hash VARCHAR(64),
    prev_chain_hash VARCHAR(64),
    chain_hash VARCHAR(64),
    ...
);

-- Signatures table
CREATE TABLE chain_signatures (
    batch_root_hash VARCHAR(64),
    signature TEXT,
    key_id VARCHAR(255),
    seq_start BIGINT,
    seq_end BIGINT,
    ...
);
```

### Key Management

- **Private Key**: Stored in environment variable (MVP) or KMS (production)
- **Public Key**: Can be distributed for independent verification
- **Key Rotation**: Supported via `key_id` field

## Security Considerations

1. **Key Security**: Private keys must be protected (use KMS in production)
2. **Hash Collisions**: SHA-256 is collision-resistant (sufficient for this use case)
3. **Signature Replay**: Signatures are tied to specific batch root hashes
4. **Chain Replay**: Cannot insert events in the past (breaks chain)

## Future Enhancements

1. **External Anchoring**: Anchor batch root hashes to public blockchain or timestamp authority
2. **Merkle Trees**: Use Merkle trees for more efficient batch verification
3. **Zero-Knowledge Proofs**: Prove chain integrity without revealing events (future)

