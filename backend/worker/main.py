"""
Kafka consumer worker that processes events and computes cryptographic chains
"""
import os
import json
import time
import hashlib
import psycopg2
from psycopg2.extras import RealDictCursor, Json
from kafka import KafkaConsumer
from typing import Dict, Any, Optional
from datetime import datetime
import uuid

from backend.worker import crypto

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://aapm:aapm_dev_password@localhost:5432/aapm")
KAFKA_BOOTSTRAP_SERVERS = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
KAFKA_TOPIC = "agent-events"

# Batch signing configuration
SIGN_BATCH_SIZE = 100  # Sign every N events
SIGN_INTERVAL_SECONDS = 60  # Or every N seconds


def get_connection():
    """Get database connection"""
    return psycopg2.connect(DATABASE_URL)


def get_or_create_agent(conn, org_id: str, agent_id: str, agent_name: Optional[str], 
                       framework: str, assistant_id: Optional[str], 
                       environment_id: Optional[str]) -> uuid.UUID:
    """Get or create agent record"""
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    
    try:
        # Try to find existing agent
        cursor.execute("""
            SELECT id FROM agents
            WHERE org_id = %s AND assistant_id = %s AND framework = %s
        """, (org_id, assistant_id, framework))
        
        result = cursor.fetchone()
        if result:
            return result['id']
        
        # Create new agent
        cursor.execute("""
            INSERT INTO agents (org_id, name, framework, assistant_id, environment_id)
            VALUES (%s, %s, %s, %s, %s)
            RETURNING id
        """, (org_id, agent_name, framework, assistant_id, environment_id))
        
        agent_uuid = cursor.fetchone()['id']
        conn.commit()
        return agent_uuid
    finally:
        cursor.close()


def get_previous_chain_hash(conn, org_id: str, agent_uuid: uuid.UUID) -> str:
    """Get the chain hash of the last event for this agent"""
    cursor = conn.cursor()
    
    try:
        cursor.execute("""
            SELECT chain_hash FROM event_chain
            WHERE org_id = %s AND agent_id = %s
            ORDER BY seq_no DESC
            LIMIT 1
        """, (org_id, agent_uuid))
        
        result = cursor.fetchone()
        return result[0] if result else "0" * 64  # Genesis hash
    finally:
        cursor.close()


def process_event(conn, event: Dict[str, Any]):
    """Process a single event: store it and compute chain"""
    org_id = event.get("org_id")
    agent_id = event.get("agent_id")  # String ID from SDK
    agent_name = event.get("agent_name")
    framework = event.get("framework", "openai")  # Default to OpenAI
    assistant_id = event.get("assistant_id") or agent_id
    environment_id = event.get("environment_id", "default")
    
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    
    try:
        # Get or create agent
        agent_uuid = get_or_create_agent(
            conn, org_id, agent_id, agent_name, framework, assistant_id, environment_id
        )
        
        # Compute event hash
        event_hash = crypto.compute_event_hash(event)
        
        # Get previous chain hash
        prev_chain_hash = get_previous_chain_hash(conn, org_id, agent_uuid)
        
        # Compute chain hash
        chain_hash = crypto.compute_chain_hash(event_hash, prev_chain_hash)
        
        # Prepare metadata JSON
        data_sources = event.get("data_sources") or []
        # Convert data sources to dicts if they're Pydantic models
        data_sources_list = []
        for ds in data_sources:
            if hasattr(ds, 'model_dump'):
                data_sources_list.append(ds.model_dump())
            elif isinstance(ds, dict):
                data_sources_list.append(ds)
            else:
                data_sources_list.append({"type": str(ds), "identifier": ""})
        
        metadata = {
            "tool_name": event.get("tool_name"),
            "tool_target": event.get("tool_target"),
            "data_sources": data_sources_list,
            "user_query_hash": event.get("user_query_hash"),
            "user_query_token_count": event.get("user_query_token_count"),
            "user_query_length": event.get("user_query_length"),
            "metadata": event.get("metadata")
        }
        
        # Parse timestamp
        timestamp_str = event.get("server_timestamp") or event.get("timestamp")
        if timestamp_str:
            try:
                timestamp = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
            except:
                timestamp = datetime.utcnow()
        else:
            timestamp = datetime.utcnow()
        
        # Insert event
        cursor.execute("""
            INSERT INTO agent_events (
                org_id, agent_id, event_type, ts, metadata_json, payload_hash, event_hash
            ) VALUES (%s, %s, %s, %s, %s, %s, %s)
            RETURNING id
        """, (
            org_id,
            agent_uuid,
            event.get("event_type"),
            timestamp,
            Json(metadata),
            event_hash,  # payload_hash same as event_hash for now
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
        
        conn.commit()
        
        return agent_uuid, chain_hash
    except Exception as e:
        conn.rollback()
        print(f"Error processing event: {e}")
        raise


def sign_batch(conn, org_id: str, agent_uuid: uuid.UUID, seq_start: int, seq_end: int):
    """Sign a batch of chain entries"""
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    
    try:
        # Get chain hashes in batch
        cursor.execute("""
            SELECT chain_hash FROM event_chain
            WHERE org_id = %s AND agent_id = %s
            AND seq_no >= %s AND seq_no <= %s
            ORDER BY seq_no ASC
        """, (org_id, agent_uuid, seq_start, seq_end))
        
        chain_hashes = [row['chain_hash'] for row in cursor.fetchall()]
        
        if not chain_hashes:
            return
        
        # Compute batch root hash (hash of all chain hashes concatenated)
        batch_root = "".join(chain_hashes)
        batch_root_hash = hashlib.sha256(batch_root.encode('utf-8')).hexdigest()
        
        # Sign it
        signature_data = crypto.sign_batch_root(batch_root_hash)
        if not signature_data:
            print("Warning: No signing key available, skipping signature")
            return
        
        # Store signature
        cursor.execute("""
            INSERT INTO chain_signatures (
                org_id, agent_id, key_id, batch_root_hash, signature, seq_start, seq_end
            ) VALUES (%s, %s, %s, %s, %s, %s, %s)
        """, (
            org_id,
            agent_uuid,
            signature_data["key_id"],
            batch_root_hash,
            signature_data["signature"],
            seq_start,
            seq_end
        ))
        
        conn.commit()
        print(f"Signed batch: agent={agent_uuid}, seq={seq_start}-{seq_end}, root={batch_root_hash[:16]}...")
    finally:
        cursor.close()


def main():
    """Main worker loop"""
    print("Starting AAPM worker...")
    print(f"Kafka: {KAFKA_BOOTSTRAP_SERVERS}")
    print(f"Database: {DATABASE_URL.split('@')[1] if '@' in DATABASE_URL else DATABASE_URL}")
    
    consumer = KafkaConsumer(
        KAFKA_TOPIC,
        bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS.split(','),
        value_deserializer=lambda m: json.loads(m.decode('utf-8')),
        auto_offset_reset='earliest',
        enable_auto_commit=True,
        group_id='aapm-worker'
    )
    
    conn = get_connection()
    
    # Track events per agent for batch signing
    agent_event_counts: Dict[tuple, int] = {}  # (org_id, agent_uuid) -> count
    last_sign_time: Dict[tuple, float] = {}  # (org_id, agent_uuid) -> timestamp
    
    try:
        print(f"Consuming from topic: {KAFKA_TOPIC}")
        
        for message in consumer:
            try:
                event = message.value
                
                # Process event
                agent_uuid, chain_hash = process_event(conn, event)
                
                org_id = event.get("org_id")
                key = (org_id, agent_uuid)
                
                # Track for batch signing
                agent_event_counts[key] = agent_event_counts.get(key, 0) + 1
                current_time = time.time()
                
                # Check if we should sign a batch
                should_sign = False
                if agent_event_counts[key] >= SIGN_BATCH_SIZE:
                    should_sign = True
                    agent_event_counts[key] = 0
                elif key not in last_sign_time or (current_time - last_sign_time[key]) >= SIGN_INTERVAL_SECONDS:
                    should_sign = True
                
                if should_sign:
                    # Get current seq_no range
                    cursor = conn.cursor()
                    cursor.execute("""
                        SELECT MIN(seq_no) as min_seq, MAX(seq_no) as max_seq
                        FROM event_chain
                        WHERE org_id = %s AND agent_id = %s
                        AND id NOT IN (
                            SELECT DISTINCT ON (org_id, agent_id) id
                            FROM event_chain
                            WHERE org_id = %s AND agent_id = %s
                            ORDER BY org_id, agent_id, seq_no DESC
                            LIMIT 1
                        )
                    """, (org_id, agent_uuid, org_id, agent_uuid))
                    
                    result = cursor.fetchone()
                    cursor.close()
                    
                    if result and result[0] and result[1]:
                        sign_batch(conn, org_id, agent_uuid, result[0], result[1])
                    
                    last_sign_time[key] = current_time
                
            except Exception as e:
                print(f"Error processing message: {e}")
                import traceback
                traceback.print_exc()
                continue
    
    except KeyboardInterrupt:
        print("\nShutting down worker...")
    finally:
        consumer.close()
        conn.close()


if __name__ == "__main__":
    main()

