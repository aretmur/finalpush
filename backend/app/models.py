"""
Pydantic models for API requests/responses
"""
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime


class DataSource(BaseModel):
    """Data source accessed by agent"""
    type: str  # file, database, api, vector_store
    identifier: str  # e.g., "file_xyz", "db:customers", "api:stripe"
    access_type: Optional[str] = None  # read, write, delete


class EventIngest(BaseModel):
    """Event payload from SDK"""
    agent_id: str
    agent_name: Optional[str] = None
    environment_id: Optional[str] = "default"
    event_type: str = Field(..., pattern="^(agent_created|tool_call|api_call|data_source_access|memory_write|memory_read|error)$")
    timestamp: Optional[str] = None  # ISO 8601, defaults to server time if not provided
    tool_name: Optional[str] = None
    tool_target: Optional[str] = None
    data_sources: Optional[List[DataSource]] = None
    user_query_hash: Optional[str] = None  # SHA-256 hash of user query (not plaintext)
    user_query_token_count: Optional[int] = None
    user_query_length: Optional[int] = None
    metadata: Optional[Dict[str, Any]] = None  # Additional context


class AgentResponse(BaseModel):
    """Agent information"""
    id: str
    org_id: str
    name: Optional[str]
    framework: str
    assistant_id: Optional[str]
    environment_id: Optional[str]
    created_at: datetime


class EventResponse(BaseModel):
    """Event response"""
    id: str
    org_id: str
    agent_id: str
    event_type: str
    ts: datetime
    metadata_json: Optional[Dict[str, Any]]
    payload_hash: Optional[str]
    event_hash: str


class ChainVerificationResult(BaseModel):
    """Chain verification result"""
    valid: bool
    org_id: str
    agent_id: str
    total_events: int
    first_bad_seq: Optional[int] = None
    computed_root: Optional[str] = None
    stored_root: Optional[str] = None
    signature_valid: Optional[bool] = None
    error: Optional[str] = None

