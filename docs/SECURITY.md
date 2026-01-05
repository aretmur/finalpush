# Security Model

## Threat Model

### Assumptions

1. **Trusted Infrastructure**: We assume the AAPM backend infrastructure (database, Kafka, worker) is trusted and not compromised.
2. **API Key Security**: API keys are stored as SHA-256 hashes. If an API key is compromised, it can be rotated.
3. **Network Security**: All communication should use TLS in production (not enforced in MVP).

### Threats

#### 1. Event Tampering

**Threat**: An attacker modifies stored events to hide malicious activity.

**Mitigation**:
- Cryptographic hash chaining: Any modification breaks the chain
- Digital signatures on batch roots: Proves origin and prevents retroactive fabrication
- Immutable append-only log structure

**Detection**: Chain verification endpoint detects tampering immediately.

#### 2. API Key Theft

**Threat**: API key is stolen and used to inject false events.

**Mitigation**:
- API keys stored as hashes (cannot be recovered)
- Rate limiting (future)
- Key rotation capability
- Audit logs of API key usage

**Response**: Rotate API key immediately, invalidate old key.

#### 3. Data Exfiltration

**Threat**: Sensitive data (user queries, PII) is stored or leaked.

**Mitigation**:
- **Data Minimization**: User queries are hashed, not stored in plaintext
- Only metadata and hashes are stored
- Data sources identified by identifier, not content
- No raw payload storage

**Best Practice**: Customers should hash sensitive data before sending to AAPM.

#### 4. Denial of Service

**Threat**: Attacker floods API with events.

**Mitigation**:
- Rate limiting per API key (future)
- Kafka buffering prevents backend overload
- Async processing prevents blocking

#### 5. Signature Key Compromise

**Threat**: Signing private key is stolen.

**Mitigation**:
- Key rotation support (key_id in signatures)
- Keys stored in environment variables (MVP)
- Future: Use KMS (AWS KMS, HashiCorp Vault)

**Response**: Rotate key, re-sign recent batches if needed.

## Data Minimization

### What We Store

- **Agent metadata**: Name, framework, assistant_id
- **Event metadata**: Event type, timestamps, tool names
- **Data source identifiers**: e.g., "file_xyz", "db:customers" (not content)
- **Hashes**: User query hashes, event hashes, chain hashes
- **Token counts**: User query token count (not content)

### What We DON'T Store

- **User queries**: Only hashes are stored
- **Data content**: Only identifiers
- **API responses**: Not captured
- **Model outputs**: Not captured
- **Raw payloads**: Only hashed versions

### Privacy Considerations

1. **User Query Hashing**: Customers should hash queries before sending if they contain PII.
2. **Data Source Naming**: Use generic identifiers, not actual file paths with PII.
3. **Retention**: 90-day default retention (configurable).

## Access Control (MVP)

### Current Implementation

- **API Key Authentication**: Simple API key in header
- **Organization Isolation**: Events scoped by org_id
- **No RBAC**: All users with API key have full access

### Future Enhancements

- SSO integration (SAML, OIDC)
- Role-based access control (RBAC)
- Fine-grained permissions
- Audit logs of admin actions

## Cryptographic Guarantees

### Integrity

- **Event Hashing**: SHA-256 hash of canonicalized event payload
- **Hash Chaining**: Each event's chain_hash depends on previous event
- **Tamper Detection**: Any modification breaks the chain (detectable)

### Attribution

- **Digital Signatures**: Ed25519 signatures on batch root hashes
- **Key ID Tracking**: Signatures include key_id for rotation support
- **Timestamping**: Signed_at timestamp for each signature

### Auditability

- **Independent Verification**: Anyone with public key can verify signatures
- **Chain Verification**: Endpoint allows verification without AAPM system
- **Export Capability**: Events can be exported with hashes and signatures

## Key Management

### MVP

- Private key stored in environment variable `AAPM_SIGNING_KEY`
- Key ID stored in `AAPM_KEY_ID`
- No key rotation automation

### Production Recommendations

1. **Use KMS**: AWS KMS, Google Cloud KMS, or HashiCorp Vault
2. **Key Rotation**: Rotate keys periodically (e.g., every 90 days)
3. **Key Versioning**: Support multiple active keys during rotation
4. **Backup**: Secure backup of signing keys (encrypted)

## Compliance

### SOC 2

- Cryptographic audit trails provide evidence of integrity
- Access logs (API key usage) for access control
- Data minimization supports privacy requirements

### GDPR

- Data minimization: Only hashes and metadata stored
- Right to deletion: Events can be deleted (breaks chain - documented)
- Data portability: Export capability with verification

### ISO 27001

- Cryptographic controls for integrity
- Access control (API keys)
- Audit trails (event chain)

## Recommendations

1. **Use TLS**: Always use HTTPS in production
2. **Rotate Keys**: Rotate API keys and signing keys periodically
3. **Monitor**: Monitor for unusual activity (future)
4. **Backup**: Regular backups of database (including chain data)
5. **Key Storage**: Use KMS for signing keys in production

