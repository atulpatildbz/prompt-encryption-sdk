# Attested Confidential Inference

A library for Confidential Inference that establishes an end-to-end, attested TLS channel to a workload in a Trusted Execution Environment (TEE).

## Installation

```bash
pip install google-cloud-confidential-inference
```

## Usage

```python
from attested_confidential_inference.client import PromptEncryptionClient
from attested_confidential_inference.proto import attestation_pb2

# Define the attestation policy
policy = attestation_pb2.AttestationPolicy(
    # ... policy configuration ...
)

# Initialize the client
# Auto-revalidate every 55 minutes (default)
client = PromptEncryptionClient(policy)

# Use the client to make requests
with client.session() as session:
    response = session.post("https://server/infer", json={"data": "..."})
    print(response.json())
```

## Server Side Primitives

This library provides low-level primitives for implementing an Attested TLS server. High-level WSGI/ASGI middlewares are also available in `attested_confidential_inference.server`.

```python
from attested_confidential_inference import server
from attested_confidential_inference.proto import attestation_pb2

# 1. Initialize Key and Token Managers (handles key rotation and GCA tokens)
key_manager = server.KeyManager()
token_manager = server.TokenManager(key_manager=key_manager)

# 2. Initialize the Attestation Engine
attested_server = server.AttestedTLS(token_manager=token_manager)

# 3. Handle Attestation Requests (e.g., inside a connection handler)
# `ssl_obj` is the SSL socket object from the connection.
def handle_attestation(request_proto, ssl_obj):
    try:
        response = attested_server.attest_connection(
            request_proto, ssl_obj=ssl_obj, label="EXPORTER-Confidential-Inference"
        )
        return response
    except ValueError as e:
        # Handle validation errors
        print(f"Attestation failed: {e}")

# The token manager runs in a separate thread for key/token rotation and
# must be used as a context manager:
with token_manager:
    # Your server logic that uses handle_attestation would go here.
    # For example, handling requests to '/_attest-connection'.
    print("Server running with token manager...")
```


## License

Apache 2.0 - See [LICENSE](LICENSE) for more information.

