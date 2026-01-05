"""
Basic example: Using AAPM SDK with OpenAI Assistants
"""
import os
from aapm import OpenAI

# Configuration
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
AAPM_API_KEY = os.getenv("AAPM_API_KEY", "test-key-123")
AAPM_ENDPOINT = os.getenv("AAPM_ENDPOINT", "http://localhost:8000")
AAPM_ORG_ID = os.getenv("AAPM_ORG_ID", "test-org")

# Create AAPM client (drop-in replacement for OpenAI)
client = OpenAI(
    api_key=OPENAI_API_KEY,
    aapm_api_key=AAPM_API_KEY,
    aapm_endpoint=AAPM_ENDPOINT,
    aapm_org_id=AAPM_ORG_ID,
    aapm_env_id="production"
)

# Create an assistant
assistant = client.beta.assistants.create(
    name="Math Tutor",
    instructions="You are a helpful math tutor.",
    model="gpt-4",
    tools=[{"type": "code_interpreter"}]
)

print(f"Created assistant: {assistant.id}")

# Create a thread
thread = client.beta.threads.create()

# Add a message
message = client.beta.threads.messages.create(
    thread_id=thread.id,
    role="user",
    content="What is 2+2?"
)

# Create a run
run = client.beta.threads.runs.create(
    thread_id=thread.id,
    assistant_id=assistant.id
)

print(f"Created run: {run.id}")
print("Events are being sent to AAPM in the background...")

