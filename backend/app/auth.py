"""
Simple API key authentication for MVP
"""
import hashlib
import os
from typing import Optional
import psycopg2
from psycopg2.extras import RealDictCursor

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://aapm:aapm_dev_password@localhost:5432/aapm")


def hash_api_key(api_key: str) -> str:
    """Compute SHA-256 hash of API key"""
    return hashlib.sha256(api_key.encode('utf-8')).hexdigest()


def validate_api_key(api_key: str) -> Optional[str]:
    """
    Validate API key and return org_id if valid.
    Returns None if invalid.
    """
    api_key_hash = hash_api_key(api_key)
    
    conn = psycopg2.connect(DATABASE_URL)
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    
    try:
        cursor.execute("""
            SELECT org_id FROM api_keys
            WHERE api_key_hash = %s
        """, (api_key_hash,))
        
        result = cursor.fetchone()
        if result:
            org_id = result['org_id']
            # Update last_used_at
            cursor.execute("""
                UPDATE api_keys
                SET last_used_at = NOW()
                WHERE api_key_hash = %s
            """, (api_key_hash,))
            conn.commit()
            return org_id
        return None
    finally:
        cursor.close()
        conn.close()


def create_api_key(org_id: str, api_key: str) -> bool:
    """Create a new API key for an organization"""
    api_key_hash = hash_api_key(api_key)
    
    conn = psycopg2.connect(DATABASE_URL)
    cursor = conn.cursor()
    
    try:
        cursor.execute("""
            INSERT INTO api_keys (org_id, api_key_hash)
            VALUES (%s, %s)
            ON CONFLICT (org_id) DO UPDATE
            SET api_key_hash = EXCLUDED.api_key_hash
        """, (org_id, api_key_hash))
        conn.commit()
        return True
    except Exception as e:
        conn.rollback()
        print(f"Error creating API key: {e}")
        return False
    finally:
        cursor.close()
        conn.close()

