"""
Kafka producer for event ingestion
"""
import json
import os
from typing import List, Dict, Any, Optional

KAFKA_BOOTSTRAP_SERVERS = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
KAFKA_TOPIC = "agent-events"

_producer: Optional[Any] = None


def get_producer():
    """Get or create Kafka producer (singleton)"""
    global _producer
    if _producer is None:
        from kafka import KafkaProducer
        _producer = KafkaProducer(
            bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS.split(','),
            value_serializer=lambda v: json.dumps(v).encode('utf-8'),
            acks='all',  # Wait for all replicas
            retries=3
        )
    return _producer


async def send_events(events: List[Dict[str, Any]]):
    """
    Send events to Kafka topic.
    This is async but Kafka producer is sync - we run it in executor.
    """
    import asyncio
    producer = get_producer()
    
    # Send events (synchronous operation in thread pool)
    loop = asyncio.get_event_loop()
    await loop.run_in_executor(
        None,
        lambda: [producer.send(KAFKA_TOPIC, value=event) for event in events]
    )
    
    # Flush to ensure delivery
    await loop.run_in_executor(None, producer.flush)


def close():
    """Close producer (for cleanup)"""
    global _producer
    if _producer:
        _producer.close()
        _producer = None

