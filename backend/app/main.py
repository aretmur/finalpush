"""
AAPM FastAPI Application
Ingestion and Query API
"""
from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import os
from typing import Optional, List
from datetime import datetime

from backend.app import models, auth, kafka_producer, verification

app = FastAPI(title="AAPM API", version="0.1.0")

# CORS for dashboard
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],  # Next.js dev server
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Dependency to get org_id from API key
async def get_org_id(api_key: str = Header(..., alias="X-API-Key")) -> str:
    """Validate API key and return org_id"""
    org_id = auth.validate_api_key(api_key)
    if not org_id:
        raise HTTPException(status_code=401, detail="Invalid API key")
    return org_id


@app.get("/")
async def root():
    return {"message": "AAPM API", "version": "0.1.0"}


@app.post("/v1/events")
async def ingest_events(
    events: List[models.EventIngest],
    org_id: str = Depends(get_org_id)
):
    """
    Ingest agent events from SDK.
    Events are enqueued to Kafka for async processing.
    """
    if not events:
        raise HTTPException(status_code=400, detail="Empty events list")
    
    # Enrich events with org_id and server timestamp
    enriched_events = []
    for event in events:
        event_dict = event.model_dump()
        event_dict["org_id"] = org_id
        event_dict["server_timestamp"] = datetime.utcnow().isoformat() + "Z"
        enriched_events.append(event_dict)
    
    # Send to Kafka
    try:
        await kafka_producer.send_events(enriched_events)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to enqueue events: {str(e)}")
    
    return {"status": "accepted", "count": len(events)}


@app.get("/v1/agents")
async def list_agents(
    org_id: str = Depends(get_org_id),
    limit: int = 100,
    offset: int = 0
):
    """List agents for an organization"""
    from backend.app import db
    agents = await db.get_agents(org_id, limit=limit, offset=offset)
    return {"agents": agents, "count": len(agents)}


@app.get("/v1/agents/{agent_id}/events")
async def get_agent_events(
    agent_id: str,
    org_id: str = Depends(get_org_id),
    from_time: Optional[str] = None,
    to_time: Optional[str] = None,
    limit: int = 1000,
    offset: int = 0
):
    """Get events for a specific agent"""
    from backend.app import db
    events = await db.get_agent_events(
        org_id, agent_id, from_time, to_time, limit, offset
    )
    return {"events": events, "count": len(events)}


@app.get("/v1/agents/{agent_id}/summary")
async def get_agent_summary(
    agent_id: str,
    org_id: str = Depends(get_org_id)
):
    """Get summary statistics for an agent"""
    from backend.app import db
    summary = await db.get_agent_summary(org_id, agent_id)
    return summary


@app.get("/v1/verify/chain")
async def verify_chain(
    agent_id: str,
    org_id: str = Depends(get_org_id),
    from_time: Optional[str] = None,
    to_time: Optional[str] = None
):
    """
    Verify chain integrity for an agent's events.
    Returns verification report with integrity status.
    """
    result = await verification.verify_chain(org_id, agent_id, from_time, to_time)
    return result


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)

