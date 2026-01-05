"""
Cryptographic operations for event integrity
"""
import hashlib
import json
from typing import Dict, Any, Optional
import os
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization


def canonical_json(data: Dict[str, Any]) -> str:
    """
    Convert dict to canonical JSON string.
    Sorted keys, no whitespace, deterministic encoding.
    """
    return json.dumps(data, sort_keys=True, separators=(',', ':'), ensure_ascii=False)


def compute_event_hash(event_payload: Dict[str, Any]) -> str:
    """
    Compute SHA-256 hash of canonicalized event payload.
    Excludes sensitive fields like user_query (only includes hash).
    """
    # Create safe payload (without sensitive data)
    safe_payload = {
        "agent_id": event_payload.get("agent_id"),
        "event_type": event_payload.get("event_type"),
        "timestamp": event_payload.get("timestamp") or event_payload.get("server_timestamp"),
        "tool_name": event_payload.get("tool_name"),
        "tool_target": event_payload.get("tool_target"),
        "data_sources": event_payload.get("data_sources"),
        "user_query_hash": event_payload.get("user_query_hash"),  # Only hash, not plaintext
        "user_query_token_count": event_payload.get("user_query_token_count"),
        "user_query_length": event_payload.get("user_query_length"),
        "metadata": event_payload.get("metadata")
    }
    
    # Remove None values for canonicalization
    safe_payload = {k: v for k, v in safe_payload.items() if v is not None}
    
    canonical = canonical_json(safe_payload)
    return hashlib.sha256(canonical.encode('utf-8')).hexdigest()


def compute_chain_hash(event_hash: str, prev_chain_hash: str) -> str:
    """
    Compute chain hash: SHA-256(event_hash + prev_chain_hash)
    This creates an append-only log where any modification breaks the chain.
    """
    combined = event_hash + prev_chain_hash
    return hashlib.sha256(combined.encode('utf-8')).hexdigest()


def get_signing_key() -> Optional[ed25519.Ed25519PrivateKey]:
    """
    Get Ed25519 signing key from environment variable.
    For MVP: key is base64-encoded private key.
    TODO: Use KMS in production.
    """
    key_data = os.getenv("AAPM_SIGNING_KEY")
    if not key_data:
        return None
    
    try:
        # Assume key is base64-encoded PEM
        private_key = serialization.load_pem_private_key(
            key_data.encode('utf-8'),
            password=None
        )
        if isinstance(private_key, ed25519.Ed25519PrivateKey):
            return private_key
    except Exception:
        pass
    
    return None


def sign_batch_root(batch_root_hash: str) -> Optional[Dict[str, str]]:
    """
    Sign a batch root hash with Ed25519.
    Returns signature dict with hex-encoded signature and key_id.
    """
    private_key = get_signing_key()
    if not private_key:
        return None
    
    signature = private_key.sign(batch_root_hash.encode('utf-8'))
    key_id = os.getenv("AAPM_KEY_ID", "aapm-key-v1")
    
    return {
        "signature": signature.hex(),
        "key_id": key_id,
        "algorithm": "Ed25519"
    }


def verify_signature(batch_root_hash: str, signature_hex: str, public_key_pem: str) -> bool:
    """
    Verify Ed25519 signature.
    For MVP: public key would be stored/looked up by key_id.
    """
    try:
        public_key = serialization.load_pem_public_key(
            public_key_pem.encode('utf-8')
        )
        if isinstance(public_key, ed25519.Ed25519PublicKey):
            signature = bytes.fromhex(signature_hex)
            public_key.verify(signature, batch_root_hash.encode('utf-8'))
            return True
    except Exception:
        pass
    return False

