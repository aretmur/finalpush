# AAPM Python SDK

Python SDK for AAPM (Agent Activity & Permission Monitor).

## Installation

```bash
pip install -e .
```

Or install dependencies manually:
```bash
pip install openai requests
```

## Usage

### Basic Usage

```python
from aapm import OpenAI

# Create AAPM client (drop-in replacement for OpenAI)
client = OpenAI(
    api_key="sk-...",  # Your OpenAI API key
    aapm_api_key="your-aapm-api-key",
    aapm_endpoint="http://localhost:8000",
    aapm_org_id="your-org-id"
)

# Use exactly like OpenAI client
assistant = client.beta.assistants.create(
    name="My Assistant",
    model="gpt-4"
)
```

### Environment Variables

You can also configure via environment variables:

```bash
export OPENAI_API_KEY="sk-..."
export AAPM_API_KEY="your-key"
export AAPM_ENDPOINT="http://localhost:8000"
export AAPM_ORG_ID="your-org"
export AAPM_ENV_ID="production"
export AAPM_DISABLED="false"  # Set to "true" to disable
```

### Example

See `examples/basic_example.py` for a complete example.

## Features

- **Non-blocking**: If AAPM endpoint is down, your app continues working
- **Batching**: Events are batched and sent efficiently
- **Drop-in replacement**: Same API as OpenAI SDK
- **Privacy-first**: User queries are hashed, not stored in plaintext

