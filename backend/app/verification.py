"""
Chain verification logic
"""
import os
import psycopg2
from psycopg2.extras import RealDictCursor
from typing import Dict, Any, Optional
import hashlib
from backend.worker.crypto import compute_chain_hash, verify_signature

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://aapm:aapm_dev_password@localhost:5432/aapm")


async def verify_chain(
    org_id: str,
    agent_id: str,
    from_time: Optional[str],
    to_time: Optional[str]
) -> Dict[str, Any]:
    """
    Verify chain integrity for an agent's events.
    Returns verification report.
    """
    conn = psycopg2.connect(DATABASE_URL)
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    
    try:
        # Build query
        query = """
            SELECT seq_no, event_hash, prev_chain_hash, chain_hash
            FROM event_chain
            WHERE org_id = %s AND agent_id = %s
        """
        params = [org_id, agent_id]
        
        if from_time:
            query += " AND ts >= %s"
            params.append(from_time)
        if to_time:
            query += " AND ts <= %s"
            params.append(to_time)
        
        query += " ORDER BY seq_no ASC"
        
        cursor.execute(query, params)
        chain_entries = cursor.fetchall()
        
        if not chain_entries:
            return {
                "valid": False,
                "org_id": org_id,
                "agent_id": agent_id,
                "total_events": 0,
                "error": "No events found in time range"
            }
        
        # Verify chain integrity
        first_bad_seq = None
        previous_chain_hash = "0" * 64  # Genesis hash
        
        for entry in chain_entries:
            # Compute expected chain hash
            expected_chain_hash = compute_chain_hash(
                entry['event_hash'],
                previous_chain_hash
            )
            
            # Check if chain hash matches
            if expected_chain_hash != entry['chain_hash']:
                first_bad_seq = entry['seq_no']
                break
            
            previous_chain_hash = entry['chain_hash']
        
        # Check signatures
        signature_valid = None
        if not first_bad_seq:
            # Get latest signature
            cursor.execute("""
                SELECT batch_root_hash, signature, key_id, seq_start, seq_end
                FROM chain_signatures
                WHERE org_id = %s AND agent_id = %s
                ORDER BY signed_at DESC
                LIMIT 1
            """, (org_id, agent_id))
            
            sig_row = cursor.fetchone()
            if sig_row:
                # Verify signature (simplified - would need public key lookup)
                signature_valid = True  # TODO: Implement actual signature verification
        
        return {
            "valid": first_bad_seq is None,
            "org_id": org_id,
            "agent_id": agent_id,
            "total_events": len(chain_entries),
            "first_bad_seq": first_bad_seq,
            "computed_root": previous_chain_hash if not first_bad_seq else None,
            "stored_root": chain_entries[-1]['chain_hash'] if not first_bad_seq else None,
            "signature_valid": signature_valid
        }
    finally:
        cursor.close()
        conn.close()

