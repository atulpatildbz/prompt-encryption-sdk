"""Exception hierarchy for Prompt Encryption Client."""


class PromptEncryptionError(Exception):
  """Base exception for all prompt encryption errors."""
  pass


class AttestationHandshakeError(PromptEncryptionError):
  """Raised when the attestation handshake fails (network or protocol error)."""
  pass


class AttestationVerificationError(PromptEncryptionError):
  """Raised when the cryptographic verification of the attestation fails."""
  pass


class PolicyViolationError(PromptEncryptionError):
  """Raised when the server's identity does not match the client policy."""
  pass
