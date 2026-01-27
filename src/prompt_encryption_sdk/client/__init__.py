"""Prompt Encryption Client SDK.

This package provides a client-side SDK for establishing E2E encrypted and
attested TLS connections with Confidential Space workloads.
"""

from .client import PromptEncryptionClient
from .exceptions import (
    AttestationHandshakeError,
    AttestationVerificationError,
    PromptEncryptionError,
    PolicyViolationError,
)

__all__ = (
    'PromptEncryptionClient',
    'PromptEncryptionError',
    'AttestationVerificationError',
    'PolicyViolationError',
    'AttestationHandshakeError',
)
