"""
Unit tests for cryptographic operations
"""
import pytest
from backend.worker import crypto


def test_canonical_json():
    """Test that canonical JSON is deterministic"""
    data1 = {"a": 1, "b": 2, "c": 3}
    data2 = {"c": 3, "b": 2, "a": 1}
    
    result1 = crypto.canonical_json(data1)
    result2 = crypto.canonical_json(data2)
    
    assert result1 == result2
    assert result1 == '{"a":1,"b":2,"c":3}'


def test_compute_event_hash():
    """Test event hash computation"""
    event = {
        "agent_id": "agent_123",
        "event_type": "tool_call",
        "timestamp": "2025-01-01T00:00:00Z",
        "tool_name": "code_interpreter"
    }
    
    hash1 = crypto.compute_event_hash(event)
    hash2 = crypto.compute_event_hash(event)
    
    # Should be deterministic
    assert hash1 == hash2
    assert len(hash1) == 64  # SHA-256 hex


def test_compute_chain_hash():
    """Test chain hash computation"""
    event_hash = "a" * 64
    prev_chain_hash = "b" * 64
    
    chain_hash = crypto.compute_chain_hash(event_hash, prev_chain_hash)
    
    assert len(chain_hash) == 64
    assert chain_hash != event_hash
    assert chain_hash != prev_chain_hash


def test_chain_validation():
    """Test that chain validation catches modified events"""
    # Create a chain
    genesis_hash = "0" * 64
    event1_hash = "a" * 64
    chain1_hash = crypto.compute_chain_hash(event1_hash, genesis_hash)
    
    event2_hash = "b" * 64
    chain2_hash = crypto.compute_chain_hash(event2_hash, chain1_hash)
    
    # Verify chain
    assert chain1_hash == crypto.compute_chain_hash(event1_hash, genesis_hash)
    assert chain2_hash == crypto.compute_chain_hash(event2_hash, chain1_hash)
    
    # Modify event1_hash
    modified_event1_hash = "c" * 64
    modified_chain1_hash = crypto.compute_chain_hash(modified_event1_hash, genesis_hash)
    
    # Chain should break
    assert modified_chain1_hash != chain1_hash
    # Next chain hash would be different
    modified_chain2_hash = crypto.compute_chain_hash(event2_hash, modified_chain1_hash)
    assert modified_chain2_hash != chain2_hash

