"""Constants for the Prompt Encryption SDK."""

# The endpoint for the post-handshake attestation RPC.
ATTESTATION_ENDPOINT: str = "/_attest-connection"

# Confidential Space OIDC Discovery URL
# Used to dynamically find the JWKS URI for token verification.
CS_OIDC_DISCOVERY_URL: str = (
    "https://confidentialcomputing.googleapis.com/.well-known/openid-configuration"
)

# Default JWKS URI if discovery fails (specific to Confidential Space)
CS_DEFAULT_JWKS_URI: str = (
    "https://www.googleapis.com/service_accounts/v1/metadata/jwk/signer@confidentialspace-sign.iam.gserviceaccount.com"
)

# Default Issuer
CS_DEFAULT_ISSUER: str = "https://confidentialcomputing.googleapis.com"

# TLS Exported Keying Material Parameters
EKM_LABEL: bytes = b"attested-inference-tls-ekm"
EKM_LENGTH: int = 32
NONCE_LENGTH: int = 32
