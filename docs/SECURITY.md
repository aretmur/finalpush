# AAPM Security Specification

**Version**: 1.0
**Date**: 2026-01-06

---

## 1. Security Overview

This document outlines the security model of the **Agent Activity & Permission Monitor (AAPM)**. The primary security goals are:
- **Confidentiality**: Protecting sensitive data within event logs.
- **Integrity**: Ensuring event logs are tamper-evident (covered in `INTEGRITY_SPEC.md`).
- **Availability**: Ensuring the system is resilient to denial-of-service attacks.
- **Authentication & Authorization**: Ensuring only authorized entities can access the system.

## 2. Key Management and Rotation

Cryptographic keys are the foundation of AAPM's non-repudiation guarantees. Proper management is critical.

### 2.1. Key Hierarchy

AAPM uses a two-tier key model:
1.  **Master Encryption Key**: An AES-256 key used to encrypt all private keys at rest. This key should be managed by a Key Management Service (KMS) like AWS KMS or HashiCorp Vault in production. For the demo, it is derived from an environment variable.
2.  **Signing Keys**: Ed25519 key pairs used for signing batch root hashes. Each organization has its own set of signing keys.

### 2.2. Key Storage

-   **Private Keys**: All Ed25519 private keys are encrypted using the Master Encryption Key (via Fernet symmetric encryption) before being stored in the `crypto_keys` table. They are only ever decrypted in memory just before a signing operation.
-   **Public Keys**: Public keys are stored in plaintext in the `crypto_keys` table and are safe to expose.

### 2.3. Key Rotation

To mitigate the risk of a compromised private key, AAPM supports and encourages regular key rotation.

-   **Process**: The `POST /v1/keys/rotate` endpoint initiates key rotation.
    1.  A new Ed25519 key pair is generated.
    2.  The new key is marked as `active`.
    3.  The previously active key is marked as `inactive` (`active = false`).
-   **Verification**: Old (inactive) keys are **never deleted**. They are retained indefinitely to allow for the verification of signatures created in the past. The `key_id` stored with each signature ensures that the correct public key is used during verification.

## 3. Data Privacy and Storage Isolation

### 3.1. Multi-Tenancy and Data Isolation

AAPM is a multi-tenant system. All data is strictly partitioned by `org_id` at both the API and database levels. API endpoints require an API key that is mapped to a single `org_id`, and all database queries are scoped to that `org_id`.

This prevents one organization from ever accessing another organization's data.

### 3.2. Hash Privacy Model (Excluding Sensitive Data)

To protect sensitive information that may appear in agent activities (e.g., user queries, file contents), the `event_hash` is computed on a "safe" version of the event payload. Sensitive fields are either omitted or replaced with a hash.

| Field | Handling in Hash | Rationale |
|---|---|---|
| `user_query` | Replaced with `user_query_hash` | Protects user privacy. The query itself is not needed for an audit trail of actions. |
| `file_contents` | Omitted | Avoids storing potentially large and sensitive data in the event log. |
| `api_secrets` | Omitted | Prevents secrets from ever being logged. |

This model ensures that the cryptographic proof can be shared for verification without exposing confidential information.

## 4. Authentication and Authorization

### 4.1. API Key Authentication

All access to the AAPM API is authenticated via a secret API key, passed in the `X-API-Key` HTTP header. Each key is unique to an organization.

-   **Storage**: API keys are hashed with **SHA-256** before being stored in the `api_keys` table. This prevents direct secret exposure in case of a database breach.
-   **Validation**: On each request, the provided key is hashed and compared to the stored hash.

### 4.2. Authorization

Authorization is based on the `org_id` associated with the validated API key. All operations are strictly scoped to the data owned by that organization.

## 5. Network Security

-   **TLS**: All communication with the AAPM API should be encrypted with TLS 1.2 or higher.
-   **Firewalls**: In a production environment, the database and Kafka brokers should be placed in a private network, accessible only by the backend API and worker services.

---

This security model provides a defense-in-depth approach to protecting the confidentiality, integrity, and availability of agent audit trails.
