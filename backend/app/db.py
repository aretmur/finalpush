"""
Database operations
"""
import os
import psycopg2
from psycopg2.extras import RealDictCursor, Json
from typing import List, Dict, Any, Optional
from datetime import datetime
import json

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://aapm:aapm_dev_password@localhost:5432/aapm")


def get_connection():
    """Get database connection"""
    return psycopg2.connect(DATABASE_URL)


async def get_agents(org_id: str, limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
    """Get list of agents for an organization"""
    conn = get_connection()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    
    try:
        cursor.execute("""
            SELECT id, org_id, name, framework, assistant_id, environment_id, created_at
            FROM agents
            WHERE org_id = %s
            ORDER BY created_at DESC
            LIMIT %s OFFSET %s
        """, (org_id, limit, offset))
        
        agents = []
        for row in cursor.fetchall():
            agents.append({
                "id": str(row['id']),
                "org_id": row['org_id'],
                "name": row['name'],
                "framework": row['framework'],
                "assistant_id": row['assistant_id'],
                "environment_id": row['environment_id'],
                "created_at": row['created_at'].isoformat()
            })
        return agents
    finally:
        cursor.close()
        conn.close()


async def get_agent_events(
    org_id: str,
    agent_id: str,
    from_time: Optional[str],
    to_time: Optional[str],
    limit: int,
    offset: int
) -> List[Dict[str, Any]]:
    """Get events for a specific agent"""
    conn = get_connection()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    
    try:
        query = """
            SELECT id, org_id, agent_id, event_type, ts, metadata_json, payload_hash, event_hash
            FROM agent_events
            WHERE org_id = %s AND agent_id = %s
        """
        params = [org_id, agent_id]
        
        if from_time:
            query += " AND ts >= %s"
            params.append(from_time)
        if to_time:
            query += " AND ts <= %s"
            params.append(to_time)
        
        query += " ORDER BY ts DESC LIMIT %s OFFSET %s"
        params.extend([limit, offset])
        
        cursor.execute(query, params)
        
        events = []
        for row in cursor.fetchall():
            events.append({
                "id": str(row['id']),
                "org_id": row['org_id'],
                "agent_id": str(row['agent_id']),
                "event_type": row['event_type'],
                "ts": row['ts'].isoformat(),
                "metadata_json": row['metadata_json'],
                "payload_hash": row['payload_hash'],
                "event_hash": row['event_hash']
            })
        return events
    finally:
        cursor.close()
        conn.close()


async def get_agent_summary(org_id: str, agent_id: str) -> Dict[str, Any]:
    """Get summary statistics for an agent"""
    conn = get_connection()
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    
    try:
        # Count by event type
        cursor.execute("""
            SELECT event_type, COUNT(*) as count
            FROM agent_events
            WHERE org_id = %s AND agent_id = %s
            GROUP BY event_type
        """, (org_id, agent_id))
        
        event_type_counts = {row['event_type']: row['count'] for row in cursor.fetchall()}
        
        # Top tools
        cursor.execute("""
            SELECT metadata_json->>'tool_name' as tool_name, COUNT(*) as count
            FROM agent_events
            WHERE org_id = %s AND agent_id = %s
            AND event_type = 'tool_call'
            AND metadata_json->>'tool_name' IS NOT NULL
            GROUP BY metadata_json->>'tool_name'
            ORDER BY count DESC
            LIMIT 10
        """, (org_id, agent_id))
        
        top_tools = [{"tool_name": row['tool_name'], "count": row['count']} for row in cursor.fetchall()]
        
        # Top data sources
        cursor.execute("""
            SELECT 
                jsonb_array_elements(metadata_json->'data_sources')->>'identifier' as data_source,
                COUNT(*) as count
            FROM agent_events
            WHERE org_id = %s AND agent_id = %s
            AND metadata_json->'data_sources' IS NOT NULL
            GROUP BY data_source
            ORDER BY count DESC
            LIMIT 10
        """, (org_id, agent_id))
        
        top_data_sources = [{"identifier": row['data_source'], "count": row['count']} for row in cursor.fetchall()]
        
        return {
            "agent_id": agent_id,
            "event_type_counts": event_type_counts,
            "top_tools": top_tools,
            "top_data_sources": top_data_sources
        }
    finally:
        cursor.close()
        conn.close()

