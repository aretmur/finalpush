"""
Integration tests for event ingestion and chain computation
"""
import pytest
import json
import time
import psycopg2
from psycopg2.extras import RealDictCursor
from backend.worker import crypto, main as worker_main

DATABASE_URL = "postgresql://aapm:aapm_dev_password@localhost:5432/aapm"


@pytest.fixture
def db_conn():
    """Database connection fixture"""
    conn = psycopg2.connect(DATABASE_URL)
    yield conn
    conn.close()


def test_event_ingestion_and_chain(db_conn):
    """Test that events are ingested and chain is computed correctly"""
    cursor = db_conn.cursor(cursor_factory=RealDictCursor)
    
    try:
        # Create test org and agent
        org_id = "test-org-integration"
        agent_id = "test-agent-integration"
        
        # Insert test agent
        cursor.execute("""
            INSERT INTO agents (org_id, name, framework, assistant_id)
            VALUES (%s, %s, %s, %s)
            ON CONFLICT (org_id, assistant_id, framework) DO UPDATE
            SET name = EXCLUDED.name
            RETURNING id
        """, (org_id, "Test Agent", "openai", agent_id))
        
        agent_uuid = cursor.fetchone()['id']
        
        # Simulate processing 5 events
        events = []
        prev_chain_hash = "0" * 64
        
        for i in range(5):
            event_payload = {
                "agent_id": agent_id,
                "event_type": "tool_call",
                "timestamp": f"2025-01-01T00:00:{i:02d}Z",
                "tool_name": f"tool_{i}"
            }
            
            event_hash = crypto.compute_event_hash(event_payload)
            chain_hash = crypto.compute_chain_hash(event_hash, prev_chain_hash)
            
            # Insert event
            cursor.execute("""
                INSERT INTO agent_events (
                    org_id, agent_id, event_type, ts, metadata_json, payload_hash, event_hash
                ) VALUES (%s, %s, %s, NOW(), %s, %s, %s)
                RETURNING id
            """, (
                org_id,
                agent_uuid,
                "tool_call",
                json.dumps({"tool_name": f"tool_{i}"}),
                event_hash,
                event_hash
            ))
            
            event_db_id = cursor.fetchone()['id']
            
            # Insert chain entry
            cursor.execute("""
                INSERT INTO event_chain (
                    org_id, agent_id, event_id, event_hash, prev_chain_hash, chain_hash
                ) VALUES (%s, %s, %s, %s, %s, %s)
            """, (
                org_id,
                agent_uuid,
                event_db_id,
                event_hash,
                prev_chain_hash,
                chain_hash
            ))
            
            events.append({
                "event_hash": event_hash,
                "chain_hash": chain_hash,
                "prev_chain_hash": prev_chain_hash
            })
            
            prev_chain_hash = chain_hash
        
        db_conn.commit()
        
        # Verify chain integrity
        cursor.execute("""
            SELECT seq_no, event_hash, prev_chain_hash, chain_hash
            FROM event_chain
            WHERE org_id = %s AND agent_id = %s
            ORDER BY seq_no ASC
        """, (org_id, agent_uuid))
        
        chain_entries = cursor.fetchall()
        
        assert len(chain_entries) == 5
        
        # Verify each link
        prev_hash = "0" * 64
        for entry in chain_entries:
            expected_chain_hash = crypto.compute_chain_hash(
                entry['event_hash'],
                prev_hash
            )
            assert entry['chain_hash'] == expected_chain_hash
            prev_hash = entry['chain_hash']
        
        # Cleanup
        cursor.execute("DELETE FROM event_chain WHERE org_id = %s", (org_id,))
        cursor.execute("DELETE FROM agent_events WHERE org_id = %s", (org_id,))
        cursor.execute("DELETE FROM agents WHERE org_id = %s", (org_id,))
        db_conn.commit()
        
    finally:
        cursor.close()


def test_chain_tamper_detection(db_conn):
    """Test that tampering is detected"""
    cursor = db_conn.cursor(cursor_factory=RealDictCursor)
    
    try:
        org_id = "test-org-tamper"
        agent_id = "test-agent-tamper"
        
        # Create agent and event
        cursor.execute("""
            INSERT INTO agents (org_id, name, framework, assistant_id)
            VALUES (%s, %s, %s, %s)
            RETURNING id
        """, (org_id, "Test", "openai", agent_id))
        
        agent_uuid = cursor.fetchone()['id']
        
        event_hash = "a" * 64
        prev_hash = "0" * 64
        chain_hash = crypto.compute_chain_hash(event_hash, prev_hash)
        
        cursor.execute("""
            INSERT INTO agent_events (org_id, agent_id, event_type, event_hash)
            VALUES (%s, %s, %s, %s)
            RETURNING id
        """, (org_id, agent_uuid, "tool_call", event_hash))
        
        event_db_id = cursor.fetchone()['id']
        
        cursor.execute("""
            INSERT INTO event_chain (org_id, agent_id, event_id, event_hash, prev_chain_hash, chain_hash)
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (org_id, agent_uuid, event_db_id, event_hash, prev_hash, chain_hash))
        
        db_conn.commit()
        
        # Tamper: modify event_hash in chain
        cursor.execute("""
            UPDATE event_chain
            SET event_hash = %s
            WHERE org_id = %s AND agent_id = %s
        """, ("b" * 64, org_id, agent_uuid))
        
        db_conn.commit()
        
        # Verify chain should be broken
        cursor.execute("""
            SELECT event_hash, prev_chain_hash, chain_hash
            FROM event_chain
            WHERE org_id = %s AND agent_id = %s
        """, (org_id, agent_uuid))
        
        entry = cursor.fetchone()
        expected_chain_hash = crypto.compute_chain_hash(entry['event_hash'], entry['prev_chain_hash'])
        
        # Chain should be broken
        assert entry['chain_hash'] != expected_chain_hash
        
        # Cleanup
        cursor.execute("DELETE FROM event_chain WHERE org_id = %s", (org_id,))
        cursor.execute("DELETE FROM agent_events WHERE org_id = %s", (org_id,))
        cursor.execute("DELETE FROM agents WHERE org_id = %s", (org_id,))
        db_conn.commit()
        
    finally:
        cursor.close()

