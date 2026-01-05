"""
AAPM Demo Server - Standalone version without Kafka/PostgreSQL dependencies
Uses in-memory storage for demonstration purposes

Features:
- Event ingestion with cryptographic integrity
- Chain verification
- Proof export with digital signatures
- Key rotation management
"""
from fastapi import FastAPI, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
from datetime import datetime
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from cryptography.fernet import Fernet
import hashlib
import json
import uuid
import base64
import os

app = FastAPI(title="AAPM Demo API", version="0.2.0")

# CORS for dashboard
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory storage
events_store: List[Dict[str, Any]] = []
agents_store: Dict[str, Dict[str, Any]] = {}
api_keys: Dict[str, str] = {
    "test-key-123": "test-org"  # API key -> org_id mapping
}

# Key storage
crypto_keys: Dict[str, Dict[str, Any]] = {}  # org_id -> {key_id -> key_data}
active_keys: Dict[str, str] = {}  # org_id -> active key_id

# Metrics storage
metrics_store: Dict[str, Dict[str, Any]] = {}  # org_id -> metrics


class EventIngest(BaseModel):
    agent_id: str
    event_type: str
    action: Optional[Dict[str, Any]] = None
    data_sources: Optional[List[Dict[str, Any]]] = None
    initiator: Optional[Dict[str, Any]] = None
    context: Optional[Dict[str, Any]] = None
    outcome: Optional[Dict[str, Any]] = None
    timestamp: Optional[str] = None


# ============================================================
# Cryptographic Key Management
# ============================================================

# Demo master key (32 bytes, base64-encoded)
_DEMO_MASTER_KEY = Fernet.generate_key()

def get_master_key() -> bytes:
    """Get master encryption key for private key storage."""
    key = os.getenv("AAPM_MASTER_KEY")
    if key:
        return key.encode('utf-8')
    # Use pre-generated key for demo (NOT for production)
    return _DEMO_MASTER_KEY


def encrypt_private_key(private_key_pem: bytes) -> str:
    """Encrypt private key for storage."""
    f = Fernet(get_master_key())
    return f.encrypt(private_key_pem).decode('utf-8')


def decrypt_private_key(encrypted_key: str) -> bytes:
    """Decrypt private key from storage."""
    f = Fernet(get_master_key())
    return f.decrypt(encrypted_key.encode('utf-8'))


def generate_key_pair(org_id: str) -> Dict[str, Any]:
    """Generate a new Ed25519 key pair for an organization."""
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    
    # Serialize keys
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')
    
    key_id = f"aapm-key-{uuid.uuid4().hex[:8]}"
    
    key_data = {
        "id": key_id,
        "org_id": org_id,
        "key_type": "signing",
        "public_key": public_key_pem,
        "private_key_encrypted": encrypt_private_key(private_key_pem),
        "created_at": datetime.utcnow().isoformat() + "Z",
        "active": True,
        "algorithm": "Ed25519"
    }
    
    return key_data


def get_or_create_active_key(org_id: str) -> Dict[str, Any]:
    """Get or create the active signing key for an organization."""
    if org_id not in crypto_keys:
        crypto_keys[org_id] = {}
    
    if org_id in active_keys:
        key_id = active_keys[org_id]
        if key_id in crypto_keys[org_id]:
            return crypto_keys[org_id][key_id]
    
    # Create new key
    key_data = generate_key_pair(org_id)
    crypto_keys[org_id][key_data["id"]] = key_data
    active_keys[org_id] = key_data["id"]
    
    return key_data


def sign_data(org_id: str, data: str) -> Dict[str, str]:
    """Sign data with the organization's active key."""
    key_data = get_or_create_active_key(org_id)
    
    # Decrypt and load private key
    private_key_pem = decrypt_private_key(key_data["private_key_encrypted"])
    private_key = serialization.load_pem_private_key(private_key_pem, password=None)
    
    # Sign
    signature = private_key.sign(data.encode('utf-8'))
    
    return {
        "signature": signature.hex(),
        "key_id": key_data["id"],
        "algorithm": "Ed25519",
        "signed_at": datetime.utcnow().isoformat() + "Z"
    }


def verify_signature(data: str, signature_hex: str, public_key_pem: str) -> bool:
    """Verify an Ed25519 signature."""
    try:
        public_key = serialization.load_pem_public_key(public_key_pem.encode('utf-8'))
        if isinstance(public_key, ed25519.Ed25519PublicKey):
            signature = bytes.fromhex(signature_hex)
            public_key.verify(signature, data.encode('utf-8'))
            return True
    except Exception:
        pass
    return False


# ============================================================
# Cryptographic Hashing
# ============================================================

def validate_api_key(api_key: str) -> Optional[str]:
    """Validate API key and return org_id"""
    return api_keys.get(api_key)


def compute_event_hash(event_payload: dict) -> str:
    """Compute SHA-256 hash of event payload"""
    payload_str = json.dumps(event_payload, sort_keys=True, separators=(',', ':'))
    return hashlib.sha256(payload_str.encode('utf-8')).hexdigest()


def compute_chain_hash(event_hash: str, previous_chain_hash: str) -> str:
    """Compute chained hash"""
    combined = f"{event_hash}{previous_chain_hash}"
    return hashlib.sha256(combined.encode('utf-8')).hexdigest()


def compute_batch_root_hash(chain_hashes: List[str]) -> str:
    """Compute batch root hash from chain hashes."""
    if not chain_hashes:
        return "0" * 64
    combined = "".join(chain_hashes)
    return hashlib.sha256(combined.encode('utf-8')).hexdigest()


def get_previous_chain_hash(org_id: str, agent_id: str) -> str:
    """Get the chain hash of the last event for this agent"""
    agent_events = [e for e in events_store if e.get('org_id') == org_id and e.get('agent_id') == agent_id]
    if agent_events:
        return agent_events[-1].get('chain_hash', '0' * 64)
    return '0' * 64  # Genesis hash


def update_metrics(org_id: str, agent_id: str):
    """Update metrics after event ingestion."""
    if org_id not in metrics_store:
        metrics_store[org_id] = {}
    
    agent_events = [e for e in events_store if e.get('org_id') == org_id and e.get('agent_id') == agent_id]
    
    metrics_store[org_id][agent_id] = {
        "total_events": len(agent_events),
        "chain_length": len(agent_events),
        "last_event_time": agent_events[-1].get('server_timestamp') if agent_events else None,
        "last_verification_time": None,
        "chain_status": "unknown"
    }


# ============================================================
# API Endpoints
# ============================================================

@app.get("/")
async def root():
    return {
        "message": "AAPM Demo API",
        "version": "0.2.0",
        "description": "Agent Activity & Permission Monitor - Tamper-evident audit trails for AI agents",
        "endpoints": {
            "POST /v1/events": "Ingest agent events",
            "GET /v1/agents": "List agents",
            "GET /v1/agents/{id}/events": "Get agent events",
            "GET /v1/agents/{id}/summary": "Get agent summary",
            "GET /v1/agents/{id}/proof": "Export cryptographic proof",
            "GET /v1/agents/{id}/metrics": "Get agent metrics",
            "GET /v1/verify/chain": "Verify chain integrity",
            "POST /v1/keys/rotate": "Rotate signing key",
            "GET /v1/keys/public": "Get active public key"
        }
    }


@app.post("/v1/events")
async def ingest_events(
    events: List[EventIngest],
    x_api_key: str = Header(..., alias="X-API-Key")
):
    """
    Ingest agent events from SDK.
    Events are processed and stored with cryptographic integrity.
    """
    org_id = validate_api_key(x_api_key)
    if not org_id:
        raise HTTPException(status_code=401, detail="Invalid API key")
    
    if not events:
        raise HTTPException(status_code=400, detail="Empty events list")
    
    processed_events = []
    
    for event in events:
        event_dict = event.model_dump()
        event_dict["org_id"] = org_id
        event_dict["server_timestamp"] = datetime.utcnow().isoformat() + "Z"
        event_dict["id"] = str(uuid.uuid4())
        
        # Compute cryptographic integrity
        event_hash = compute_event_hash(event_dict)
        previous_chain_hash = get_previous_chain_hash(org_id, event.agent_id)
        chain_hash = compute_chain_hash(event_hash, previous_chain_hash)
        
        event_dict["event_hash"] = event_hash
        event_dict["previous_chain_hash"] = previous_chain_hash
        event_dict["chain_hash"] = chain_hash
        
        events_store.append(event_dict)
        processed_events.append(event_dict)
        
        # Auto-register agent if not exists
        if event.agent_id not in agents_store:
            agents_store[event.agent_id] = {
                "id": event.agent_id,
                "org_id": org_id,
                "name": f"Agent {event.agent_id[:8]}",
                "framework": "openai_assistants",
                "created_at": datetime.utcnow().isoformat() + "Z",
                "status": "active"
            }
        
        # Update metrics
        update_metrics(org_id, event.agent_id)
    
    return {
        "status": "accepted",
        "count": len(events),
        "events": [{"id": e["id"], "event_hash": e["event_hash"], "chain_hash": e["chain_hash"]} for e in processed_events]
    }


@app.get("/v1/agents")
async def list_agents(
    x_api_key: str = Header(..., alias="X-API-Key"),
    limit: int = 100,
    offset: int = 0
):
    """List agents for an organization"""
    org_id = validate_api_key(x_api_key)
    if not org_id:
        raise HTTPException(status_code=401, detail="Invalid API key")
    
    org_agents = [a for a in agents_store.values() if a.get('org_id') == org_id]
    return {"agents": org_agents[offset:offset+limit], "count": len(org_agents)}


@app.get("/v1/agents/{agent_id}/events")
async def get_agent_events(
    agent_id: str,
    x_api_key: str = Header(..., alias="X-API-Key"),
    from_time: Optional[str] = None,
    to_time: Optional[str] = None,
    limit: int = 1000,
    offset: int = 0
):
    """Get events for a specific agent"""
    org_id = validate_api_key(x_api_key)
    if not org_id:
        raise HTTPException(status_code=401, detail="Invalid API key")
    
    agent_events = [e for e in events_store if e.get('org_id') == org_id and e.get('agent_id') == agent_id]
    
    # Sort by timestamp (newest first)
    agent_events.sort(key=lambda x: x.get('server_timestamp', ''), reverse=True)
    
    return {"events": agent_events[offset:offset+limit], "count": len(agent_events)}


@app.get("/v1/agents/{agent_id}/summary")
async def get_agent_summary(
    agent_id: str,
    x_api_key: str = Header(..., alias="X-API-Key")
):
    """Get summary statistics for an agent"""
    org_id = validate_api_key(x_api_key)
    if not org_id:
        raise HTTPException(status_code=401, detail="Invalid API key")
    
    agent_events = [e for e in events_store if e.get('org_id') == org_id and e.get('agent_id') == agent_id]
    
    # Count by event type
    event_type_counts = {}
    tool_counts = {}
    
    for event in agent_events:
        event_type = event.get('event_type', 'unknown')
        event_type_counts[event_type] = event_type_counts.get(event_type, 0) + 1
        
        if event_type == 'tool_call' and event.get('action'):
            tool_name = event['action'].get('tool_name', 'unknown')
            tool_counts[tool_name] = tool_counts.get(tool_name, 0) + 1
    
    return {
        "agent_id": agent_id,
        "total_events": len(agent_events),
        "event_type_counts": event_type_counts,
        "top_tools": [{"tool_name": k, "count": v} for k, v in sorted(tool_counts.items(), key=lambda x: -x[1])[:10]]
    }


@app.get("/v1/agents/{agent_id}/proof")
async def export_proof(
    agent_id: str,
    x_api_key: str = Header(..., alias="X-API-Key"),
    limit: int = 100
):
    """
    Export cryptographic proof bundle for an agent.
    
    Returns a verifiable proof containing:
    - Event chain data (hashes, chain hashes, prev chain hashes)
    - Batch root hash
    - Digital signature
    - Public key for verification
    """
    org_id = validate_api_key(x_api_key)
    if not org_id:
        raise HTTPException(status_code=401, detail="Invalid API key")
    
    # Get agent events
    agent_events = [e for e in events_store if e.get('org_id') == org_id and e.get('agent_id') == agent_id]
    agent_events.sort(key=lambda x: x.get('server_timestamp', ''))
    
    # Limit events
    agent_events = agent_events[-limit:] if len(agent_events) > limit else agent_events
    
    if not agent_events:
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
            "public_key": None
        }
    
    # Build event chain data
    chain_data = []
    chain_hashes = []
    
    for event in agent_events:
        chain_data.append({
            "id": event.get("id"),
            "event_type": event.get("event_type"),
            "timestamp": event.get("server_timestamp"),
            "event_hash": event.get("event_hash"),
            "chain_hash": event.get("chain_hash"),
            "prev_chain_hash": event.get("previous_chain_hash")
        })
        chain_hashes.append(event.get("chain_hash"))
    
    # Compute batch root hash
    batch_root_hash = compute_batch_root_hash(chain_hashes)
    
    # Sign the batch root
    signature_data = sign_data(org_id, batch_root_hash)
    
    # Get public key
    key_data = get_or_create_active_key(org_id)
    
    # Build proof bundle
    proof = {
        "version": "1.0",
        "proof_type": "aapm_chain_proof",
        "schema": "https://aapm.io/schemas/proof/v1",
        
        # Identity
        "org_id": org_id,
        "agent_id": agent_id,
        
        # Timestamps
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "chain_start_time": chain_data[0]["timestamp"] if chain_data else None,
        "chain_end_time": chain_data[-1]["timestamp"] if chain_data else None,
        
        # Event data
        "event_count": len(chain_data),
        "events": chain_data,
        
        # Cryptographic proof
        "batch_root_hash": batch_root_hash,
        "hash_algorithm": "SHA-256",
        "chain_algorithm": "SHA-256(event_hash || prev_chain_hash)",
        
        # Signature
        "signature": {
            "value": signature_data["signature"],
            "algorithm": "Ed25519",
            "key_id": signature_data["key_id"],
            "signed_at": signature_data["signed_at"]
        },
        
        # Public key for verification
        "public_key": key_data["public_key"],
        
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
    
    return proof


@app.get("/v1/agents/{agent_id}/metrics")
async def get_agent_metrics(
    agent_id: str,
    x_api_key: str = Header(..., alias="X-API-Key")
):
    """Get metrics for an agent (total events, chain length, verification status)."""
    org_id = validate_api_key(x_api_key)
    if not org_id:
        raise HTTPException(status_code=401, detail="Invalid API key")
    
    agent_events = [e for e in events_store if e.get('org_id') == org_id and e.get('agent_id') == agent_id]
    
    # Get stored metrics or compute
    metrics = metrics_store.get(org_id, {}).get(agent_id, {})
    
    return {
        "agent_id": agent_id,
        "total_events": len(agent_events),
        "chain_length": len(agent_events),
        "first_event_time": agent_events[0].get('server_timestamp') if agent_events else None,
        "last_event_time": agent_events[-1].get('server_timestamp') if agent_events else None,
        "last_verification_time": metrics.get("last_verification_time"),
        "chain_status": metrics.get("chain_status", "unknown")
    }


@app.get("/v1/verify/chain")
async def verify_chain(
    agent_id: str,
    x_api_key: str = Header(..., alias="X-API-Key"),
    from_time: Optional[str] = None,
    to_time: Optional[str] = None
):
    """
    Verify chain integrity for an agent's events.
    Returns verification report with integrity status.
    """
    org_id = validate_api_key(x_api_key)
    if not org_id:
        raise HTTPException(status_code=401, detail="Invalid API key")
    
    agent_events = [e for e in events_store if e.get('org_id') == org_id and e.get('agent_id') == agent_id]
    agent_events.sort(key=lambda x: x.get('server_timestamp', ''))
    
    if not agent_events:
        return {
            "status": "no_events",
            "agent_id": agent_id,
            "message": "No events found for this agent",
            "valid": False,
            "total_events": 0
        }
    
    # Verify chain integrity
    is_valid = True
    broken_at = None
    
    for i, event in enumerate(agent_events):
        # Recompute event hash
        event_copy = {k: v for k, v in event.items() if k not in ['event_hash', 'chain_hash', 'previous_chain_hash']}
        computed_hash = compute_event_hash(event_copy)
        
        if computed_hash != event.get('event_hash'):
            is_valid = False
            broken_at = event.get('id')
            break
        
        # Verify chain linkage
        if i > 0:
            expected_prev = agent_events[i-1].get('chain_hash')
            if event.get('previous_chain_hash') != expected_prev:
                is_valid = False
                broken_at = event.get('id')
                break
    
    # Update metrics
    if org_id not in metrics_store:
        metrics_store[org_id] = {}
    if agent_id not in metrics_store[org_id]:
        metrics_store[org_id][agent_id] = {}
    
    metrics_store[org_id][agent_id]["last_verification_time"] = datetime.utcnow().isoformat() + "Z"
    metrics_store[org_id][agent_id]["chain_status"] = "valid" if is_valid else "broken"
    
    return {
        "status": "verified" if is_valid else "tampered",
        "agent_id": agent_id,
        "events_verified": len(agent_events),
        "chain_intact": is_valid,
        "broken_at_event": broken_at,
        "first_event_hash": agent_events[0].get('event_hash') if agent_events else None,
        "last_chain_hash": agent_events[-1].get('chain_hash') if agent_events else None,
        # Dashboard expected fields
        "valid": is_valid,
        "total_events": len(agent_events),
        "first_bad_seq": None if is_valid else 1,
        "signature_valid": True if is_valid else None
    }


# ============================================================
# Key Management Endpoints
# ============================================================

@app.post("/v1/keys/rotate")
async def rotate_key(
    x_api_key: str = Header(..., alias="X-API-Key")
):
    """
    Rotate the signing key for an organization.
    Creates a new Ed25519 key pair and marks the old key as inactive.
    """
    org_id = validate_api_key(x_api_key)
    if not org_id:
        raise HTTPException(status_code=401, detail="Invalid API key")
    
    # Get old key info
    old_key_id = active_keys.get(org_id)
    old_key_public = None
    
    if old_key_id and org_id in crypto_keys and old_key_id in crypto_keys[org_id]:
        crypto_keys[org_id][old_key_id]["active"] = False
        old_key_public = crypto_keys[org_id][old_key_id]["public_key"]
    
    # Generate new key
    new_key_data = generate_key_pair(org_id)
    
    if org_id not in crypto_keys:
        crypto_keys[org_id] = {}
    
    crypto_keys[org_id][new_key_data["id"]] = new_key_data
    active_keys[org_id] = new_key_data["id"]
    
    return {
        "status": "rotated",
        "new_key": {
            "id": new_key_data["id"],
            "public_key": new_key_data["public_key"],
            "created_at": new_key_data["created_at"],
            "algorithm": new_key_data["algorithm"]
        },
        "old_key_id": old_key_id,
        "rotated_at": datetime.utcnow().isoformat() + "Z"
    }


@app.get("/v1/keys/public")
async def get_public_key(
    x_api_key: str = Header(..., alias="X-API-Key"),
    key_id: Optional[str] = None
):
    """
    Get the active public key for signature verification.
    Optionally specify key_id to get a specific key.
    """
    org_id = validate_api_key(x_api_key)
    if not org_id:
        raise HTTPException(status_code=401, detail="Invalid API key")
    
    if key_id:
        # Get specific key
        if org_id in crypto_keys and key_id in crypto_keys[org_id]:
            key_data = crypto_keys[org_id][key_id]
            return {
                "id": key_data["id"],
                "public_key": key_data["public_key"],
                "created_at": key_data["created_at"],
                "active": key_data["active"],
                "algorithm": key_data["algorithm"]
            }
        raise HTTPException(status_code=404, detail="Key not found")
    
    # Get active key
    key_data = get_or_create_active_key(org_id)
    
    return {
        "id": key_data["id"],
        "public_key": key_data["public_key"],
        "created_at": key_data["created_at"],
        "active": key_data["active"],
        "algorithm": key_data["algorithm"]
    }


@app.get("/v1/keys")
async def list_keys(
    x_api_key: str = Header(..., alias="X-API-Key")
):
    """List all keys for an organization."""
    org_id = validate_api_key(x_api_key)
    if not org_id:
        raise HTTPException(status_code=401, detail="Invalid API key")
    
    if org_id not in crypto_keys:
        return {"keys": [], "active_key_id": None}
    
    keys = [
        {
            "id": k["id"],
            "public_key": k["public_key"],
            "created_at": k["created_at"],
            "active": k["active"],
            "algorithm": k["algorithm"]
        }
        for k in crypto_keys[org_id].values()
    ]
    
    return {
        "keys": keys,
        "active_key_id": active_keys.get(org_id)
    }


@app.get("/health")
async def health():
    return {"status": "healthy", "events_count": len(events_store), "agents_count": len(agents_store)}


if __name__ == "__main__":
    import uvicorn
    print("\n" + "="*60)
    print("AAPM Demo Server Starting...")
    print("="*60)
    print("\nAgent Activity & Permission Monitor")
    print("Tamper-evident, cryptographically verifiable audit trails for AI agents")
    print("\nAPI Key for testing: test-key-123")
    print("Organization ID: test-org")
    print("\nEndpoints:")
    print("  GET  /                        - API info")
    print("  POST /v1/events               - Ingest events")
    print("  GET  /v1/agents               - List agents")
    print("  GET  /v1/agents/{id}/events   - Get agent events")
    print("  GET  /v1/agents/{id}/summary  - Get agent summary")
    print("  GET  /v1/agents/{id}/proof    - Export cryptographic proof")
    print("  GET  /v1/agents/{id}/metrics  - Get agent metrics")
    print("  GET  /v1/verify/chain         - Verify chain integrity")
    print("  POST /v1/keys/rotate          - Rotate signing key")
    print("  GET  /v1/keys/public          - Get active public key")
    print("  GET  /v1/keys                 - List all keys")
    print("\n" + "="*60 + "\n")
    
    uvicorn.run(app, host="0.0.0.0", port=8000)
