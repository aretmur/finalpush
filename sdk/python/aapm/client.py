"""
AAPM Client - OpenAI SDK wrapper
"""
import os
import time
import threading
import hashlib
from queue import Queue
from typing import Dict, Any, Optional, List
import requests
from datetime import datetime

# Try to import OpenAI, but don't fail if not available
try:
    from openai import OpenAI as BaseOpenAI
    OPENAI_AVAILABLE = True
except ImportError:
    OPENAI_AVAILABLE = False
    BaseOpenAI = None


class AAPMClient:
    """
    AAPM client that wraps OpenAI SDK and emits events.
    Non-blocking: if AAPM endpoint is down, continues without raising.
    """
    
    def __init__(
        self,
        api_key: str,
        aapm_api_key: Optional[str] = None,
        aapm_endpoint: Optional[str] = None,
        aapm_org_id: Optional[str] = None,
        aapm_env_id: Optional[str] = None,
        aapm_disabled: bool = False
    ):
        if not OPENAI_AVAILABLE:
            raise ImportError("OpenAI SDK not installed. Install with: pip install openai")
        
        self.openai_client = BaseOpenAI(api_key=api_key)
        
        # AAPM configuration
        self.aapm_disabled = aapm_disabled or os.getenv("AAPM_DISABLED", "false").lower() == "true"
        self.aapm_api_key = aapm_api_key or os.getenv("AAPM_API_KEY")
        self.aapm_endpoint = (aapm_endpoint or os.getenv("AAPM_ENDPOINT", "http://localhost:8000")).rstrip('/')
        self.aapm_org_id = aapm_org_id or os.getenv("AAPM_ORG_ID")
        self.aapm_env_id = aapm_env_id or os.getenv("AAPM_ENV_ID", "default")
        
        # Event batching
        self.event_queue = Queue()
        self.batch_size = 100
        self.flush_interval = 5  # seconds
        
        # Track agents
        self.agents: Dict[str, Dict[str, Any]] = {}  # agent_id -> agent_info
        
        # Start background thread for batching
        if not self.aapm_disabled:
            self._batch_thread = threading.Thread(target=self._batch_processor, daemon=True)
            self._batch_thread.start()
    
    def _capture_event(self, event: Dict[str, Any]):
        """Add event to queue (non-blocking)"""
        if self.aapm_disabled:
            return
        
        try:
            self.event_queue.put(event, block=False)
        except:
            pass  # Queue full, drop event (non-blocking)
    
    def _batch_processor(self):
        """Background thread that batches and sends events"""
        batch = []
        last_flush = time.time()
        
        while True:
            try:
                # Collect events
                while len(batch) < self.batch_size:
                    try:
                        event = self.event_queue.get(timeout=1)
                        batch.append(event)
                    except:
                        break
                
                # Flush if batch full or time elapsed
                if len(batch) >= self.batch_size or (time.time() - last_flush) > self.flush_interval:
                    if batch:
                        self._send_batch(batch)
                        batch = []
                        last_flush = time.time()
            except Exception as e:
                # Log error, don't crash
                print(f"AAPM error: {e}")
                time.sleep(1)
    
    def _send_batch(self, batch: List[Dict[str, Any]]):
        """Send batch to AAPM ingestion API"""
        if not self.aapm_api_key or not self.aapm_endpoint:
            return
        
        try:
            response = requests.post(
                f"{self.aapm_endpoint}/v1/events",
                json=batch,
                headers={
                    "X-API-Key": self.aapm_api_key,
                    "Content-Type": "application/json"
                },
                timeout=5
            )
            response.raise_for_status()
        except Exception as e:
            # On failure, just log (non-blocking)
            # Could implement retry logic here
            pass
    
    def _hash_query(self, query: str) -> str:
        """Compute SHA-256 hash of user query (don't store plaintext)"""
        return hashlib.sha256(query.encode('utf-8')).hexdigest()
    
    # OpenAI API wrappers
    
    @property
    def beta(self):
        """Access to OpenAI beta API"""
        return BetaAPI(self)
    
    def __getattr__(self, name):
        """Delegate other attributes to OpenAI client"""
        return getattr(self.openai_client, name)


class BetaAPI:
    """Wrapper for OpenAI beta API"""
    
    def __init__(self, aapm_client: AAPMClient):
        self.aapm_client = aapm_client
        self.assistants = AssistantsAPI(aapm_client)
        self.threads = ThreadsAPI(aapm_client)


class AssistantsAPI:
    """Wrapper for OpenAI Assistants API"""
    
    def __init__(self, aapm_client: AAPMClient):
        self.aapm_client = aapm_client
    
    def create(self, **kwargs):
        """Create assistant and emit agent_created event"""
        result = self.aapm_client.openai_client.beta.assistants.create(**kwargs)
        
        agent_id = result.id
        agent_name = kwargs.get("name", "Unnamed Assistant")
        
        # Store agent info
        self.aapm_client.agents[agent_id] = {
            "name": agent_name,
            "framework": "openai",
            "assistant_id": agent_id,
            "model": kwargs.get("model"),
            "tools": kwargs.get("tools", [])
        }
        
        # Emit event
        self.aapm_client._capture_event({
            "agent_id": agent_id,
            "agent_name": agent_name,
            "environment_id": self.aapm_client.aapm_env_id,
            "event_type": "agent_created",
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "metadata": {
                "model": kwargs.get("model"),
                "tools": kwargs.get("tools", []),
                "instructions": kwargs.get("instructions")[:100] if kwargs.get("instructions") else None  # Truncate
            }
        })
        
        return result
    
    def __getattr__(self, name):
        """Delegate other methods to OpenAI client"""
        return getattr(self.aapm_client.openai_client.beta.assistants, name)


class ThreadsAPI:
    """Wrapper for OpenAI Threads API"""
    
    def __init__(self, aapm_client: AAPMClient):
        self.aapm_client = aapm_client
    
    def create(self, **kwargs):
        """Create thread"""
        return self.aapm_client.openai_client.beta.threads.create(**kwargs)
    
    def runs_create(self, thread_id: str, assistant_id: str, **kwargs):
        """Create run and monitor for tool calls"""
        # Get user query if provided
        user_query = kwargs.get("additional_instructions") or ""
        user_query_hash = None
        user_query_token_count = None
        user_query_length = None
        
        if user_query:
            user_query_hash = self.aapm_client._hash_query(user_query)
            user_query_length = len(user_query)
            # Rough token estimate (4 chars per token)
            user_query_token_count = user_query_length // 4
        
        # Create run
        run = self.aapm_client.openai_client.beta.threads.runs.create(
            thread_id=thread_id,
            assistant_id=assistant_id,
            **kwargs
        )
        
        # Poll for completion and capture tool calls
        self._monitor_run(thread_id, run.id, assistant_id, user_query_hash, user_query_token_count, user_query_length)
        
        return run
    
    def _monitor_run(self, thread_id: str, run_id: str, assistant_id: str,
                    user_query_hash: Optional[str], user_query_token_count: Optional[int],
                    user_query_length: Optional[int]):
        """Monitor run and capture tool calls"""
        # Simplified: just capture run creation
        # In production, would poll for status and capture tool_calls
        self.aapm_client._capture_event({
            "agent_id": assistant_id,
            "environment_id": self.aapm_client.aapm_env_id,
            "event_type": "tool_call",  # Simplified
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "user_query_hash": user_query_hash,
            "user_query_token_count": user_query_token_count,
            "user_query_length": user_query_length,
            "metadata": {
                "thread_id": thread_id,
                "run_id": run_id
            }
        })
    
    def __getattr__(self, name):
        """Delegate other methods to OpenAI client"""
        return getattr(self.aapm_client.openai_client.beta.threads, name)


# Convenience: export OpenAI class that's a drop-in replacement
class OpenAI(AAPMClient):
    """
    Drop-in replacement for OpenAI client.
    Usage:
        from aapm import OpenAI
        client = OpenAI(api_key="...", aapm_api_key="...", aapm_org_id="...")
    """
    pass

