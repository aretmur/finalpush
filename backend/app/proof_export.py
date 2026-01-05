"""
Cryptographic Proof Export for AAPM
Generates verifiable proof bundles for agent event chains.
"""
import hashlib
import json
from datetime import datetime
from typing import Dict, Any, List, Optional
from backend.app.crypto_keys import get_key_manager


def compute_batch_root_hash(chain_hashes: List[str]) -> str:
    """
    Compute a Merkle-like root hash from a list of chain hashes.
    For simplicity, we use a sequential hash: SHA-256(h1 || h2 || ... || hn)
    """
    if not chain_hashes:
        return "0" * 64
    
    combined = "".join(chain_hashes)
    return hashlib.sha256(combined.encode('utf-8')).hexdigest()


def generate_proof_bundle(
    org_id: str,
    agent_id: str,
    events: List[Dict[str, Any]],
    include_signature: bool = True
) -> Dict[str, Any]:
    """
    Generate a cryptographic proof bundle for a set of events.
    
    The proof bundle contains:
    - Event chain data (hashes, chain hashes, prev chain hashes)
    - Batch root hash (computed from all chain hashes)
    - Digital signature of the batch root (if signing key available)
    - Public key for verification
    - Metadata (timestamps, counts, etc.)
    
    This bundle can be independently verified offline.
    """
    if not events:
        return {
            "version": "1.0",
            "proof_type": "aapm_chain_proof",
            "org_id": org_id,
            "agent_id": agent_id,
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "event_count": 0,
            "events": [],
            "batch_root_hash": "0" * 64,
            "signature": None,
            "public_key": None,
            "verification_instructions": "No events to verify"
        }
    
    # Extract chain data from events
    chain_data = []
    chain_hashes = []
    
    for event in events:
        event_entry = {
            "id": event.get("id"),
            "event_type": event.get("event_type"),
            "timestamp": event.get("server_timestamp") or event.get("timestamp") or event.get("ts"),
            "event_hash": event.get("event_hash"),
            "chain_hash": event.get("chain_hash"),
            "prev_chain_hash": event.get("previous_chain_hash") or event.get("prev_chain_hash"),
        }
        chain_data.append(event_entry)
        if event.get("chain_hash"):
            chain_hashes.append(event.get("chain_hash"))
    
    # Sort by timestamp to ensure correct order
    chain_data.sort(key=lambda x: x.get("timestamp") or "")
    
    # Compute batch root hash
    batch_root_hash = compute_batch_root_hash(chain_hashes)
    
    # Sign the batch root
    signature_data = None
    public_key = None
    key_id = None
    
    if include_signature:
        key_manager = get_key_manager(org_id)
        signature_result = key_manager.sign_data(batch_root_hash)
        
        if signature_result:
            signature_data = signature_result["signature"]
            key_id = signature_result["key_id"]
            
            # Get public key for verification
            active_key = key_manager.get_active_key()
            if active_key:
                public_key = active_key["public_key"]
    
    # Build proof bundle
    proof_bundle = {
        "version": "1.0",
        "proof_type": "aapm_chain_proof",
        "schema": "https://aapm.io/schemas/proof/v1",
        
        # Identity
        "org_id": org_id,
        "agent_id": agent_id,
        
        # Timestamps
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "chain_start_time": chain_data[0].get("timestamp") if chain_data else None,
        "chain_end_time": chain_data[-1].get("timestamp") if chain_data else None,
        
        # Event data
        "event_count": len(chain_data),
        "events": chain_data,
        
        # Cryptographic proof
        "batch_root_hash": batch_root_hash,
        "hash_algorithm": "SHA-256",
        "chain_algorithm": "SHA-256(event_hash || prev_chain_hash)",
        
        # Signature
        "signature": {
            "value": signature_data,
            "algorithm": "Ed25519",
            "key_id": key_id,
            "signed_at": datetime.utcnow().isoformat() + "Z"
        } if signature_data else None,
        
        # Public key for verification
        "public_key": public_key,
        
        # Verification instructions
        "verification": {
            "steps": [
                "1. For each event, verify: chain_hash == SHA-256(event_hash || prev_chain_hash)",
                "2. Verify first event's prev_chain_hash is genesis ('0' * 64) or matches previous proof",
                "3. Verify each event's prev_chain_hash matches previous event's chain_hash",
                "4. Compute batch_root_hash = SHA-256(chain_hash_1 || chain_hash_2 || ... || chain_hash_n)",
                "5. Verify signature using Ed25519: verify(public_key, batch_root_hash, signature)"
            ],
            "cli_command": "python verify_chain.py proof.json"
        }
    }
    
    return proof_bundle


def verify_proof_bundle(proof_bundle: Dict[str, Any]) -> Dict[str, Any]:
    """
    Verify a proof bundle.
    Returns verification result with detailed status.
    """
    result = {
        "valid": True,
        "chain_valid": True,
        "signature_valid": None,
        "errors": [],
        "warnings": [],
        "verified_at": datetime.utcnow().isoformat() + "Z"
    }
    
    events = proof_bundle.get("events", [])
    if not events:
        result["warnings"].append("No events in proof bundle")
        return result
    
    # Sort events by timestamp
    events_sorted = sorted(events, key=lambda x: x.get("timestamp") or "")
    
    # Verify chain integrity
    chain_hashes = []
    prev_hash = "0" * 64  # Genesis hash
    
    for i, event in enumerate(events_sorted):
        event_hash = event.get("event_hash")
        chain_hash = event.get("chain_hash")
        event_prev_hash = event.get("prev_chain_hash")
        
        if not event_hash or not chain_hash:
            result["valid"] = False
            result["chain_valid"] = False
            result["errors"].append(f"Event {i}: Missing event_hash or chain_hash")
            continue
        
        # Verify prev_chain_hash linkage
        if i == 0:
            # First event should have genesis hash or match provided prev_hash
            if event_prev_hash and event_prev_hash != "0" * 64:
                result["warnings"].append(f"Event 0: Non-genesis prev_chain_hash (may be continuation)")
        else:
            expected_prev = events_sorted[i-1].get("chain_hash")
            if event_prev_hash != expected_prev:
                result["valid"] = False
                result["chain_valid"] = False
                result["errors"].append(
                    f"Event {i}: Chain broken. Expected prev_chain_hash={expected_prev[:16]}..., "
                    f"got {event_prev_hash[:16] if event_prev_hash else 'None'}..."
                )
        
        # Verify chain_hash computation
        if event_prev_hash:
            expected_chain_hash = hashlib.sha256(
                (event_hash + event_prev_hash).encode('utf-8')
            ).hexdigest()
            
            if chain_hash != expected_chain_hash:
                result["valid"] = False
                result["chain_valid"] = False
                result["errors"].append(
                    f"Event {i}: Invalid chain_hash. Expected {expected_chain_hash[:16]}..., "
                    f"got {chain_hash[:16]}..."
                )
        
        chain_hashes.append(chain_hash)
    
    # Verify batch root hash
    expected_batch_root = compute_batch_root_hash(chain_hashes)
    actual_batch_root = proof_bundle.get("batch_root_hash")
    
    if actual_batch_root != expected_batch_root:
        result["valid"] = False
        result["errors"].append(
            f"Invalid batch_root_hash. Expected {expected_batch_root[:16]}..., "
            f"got {actual_batch_root[:16] if actual_batch_root else 'None'}..."
        )
    
    # Verify signature if present
    signature_data = proof_bundle.get("signature")
    public_key_pem = proof_bundle.get("public_key")
    
    if signature_data and signature_data.get("value") and public_key_pem:
        try:
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric import ed25519
            
            public_key = serialization.load_pem_public_key(public_key_pem.encode('utf-8'))
            if isinstance(public_key, ed25519.Ed25519PublicKey):
                signature = bytes.fromhex(signature_data["value"])
                public_key.verify(signature, actual_batch_root.encode('utf-8'))
                result["signature_valid"] = True
            else:
                result["signature_valid"] = False
                result["errors"].append("Invalid public key type (expected Ed25519)")
        except Exception as e:
            result["valid"] = False
            result["signature_valid"] = False
            result["errors"].append(f"Signature verification failed: {str(e)}")
    elif signature_data:
        result["warnings"].append("Signature present but public key missing")
    else:
        result["warnings"].append("No signature in proof bundle")
    
    return result
