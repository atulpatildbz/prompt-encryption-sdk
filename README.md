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

This library provides the low-level primitives for implementing an Attested TLS server. Note that high-level WSGI/ASGI middlewares are not included in this package and must be implemented by the application.

```python
from attested_confidential_inference import attested_tls
from attested_confidential_inference.proto import attestation_pb2

# 1. Initialize Key and Token Managers (handles key rotation and GCA tokens)
key_manager = attested_tls.KeyManager()
token_manager = attested_tls.TokenManager(key_manager=key_manager)
token_manager.start()

# 2. Initialize the Attestation Engine
attested_server = attested_tls.AttestedTLS(token_manager=token_manager)

# 3. Handle Attestation Requests (e.g., inside a connection handler)
def handle_attestation(request_proto):
    try:
        response = attested_server.attest_connection(request_proto)
        return response
    except ValueError as e:
        # Handle validation errors
        print(f"Attestation failed: {e}")
```


## License

Apache 2.0 - See [LICENSE](LICENSE) for more information.
