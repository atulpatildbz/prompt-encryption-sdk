"""Provides classes for validating OIDC tokens and attestation evidence."""

from collections.abc import Mapping
import hashlib
import logging
import types
from typing import Any

from prompt_encryption_sdk.client import constants
from prompt_encryption_sdk.client import exceptions
from prompt_encryption_sdk.proto import attestation_pb2
import jwt
import requests


logger = logging.getLogger(__name__)


_GCA_STRING_BY_HW_MODEL = types.MappingProxyType({
    attestation_pb2.HARDWARE_MODEL_TDX: "GCP_INTEL_TDX",
    attestation_pb2.HARDWARE_MODEL_SEV: "GCP_AMD_SEV",
    attestation_pb2.HARDWARE_MODEL_SEV_SNP: "GCP_AMD_SEV_SNP",
})

_GCE_POLICY_FIELDS = ("project_id", "zone", "instance_id", "instance_name")


class OIDCTokenValidator:
  """Validates OIDC tokens issued by Confidential Space using PyJWT."""

  def __init__(self, session: requests.Session | None = None):
    self._session = session or requests.Session()
    self._jwks_client = None
    self._issuer = None
    self._initialize_oidc_config()

  def close(self) -> None:
    """Closes the underlying requests session."""
    self._session.close()

  def _initialize_oidc_config(self):
    """Initializes the JWKS client, preferring Discovery but falling back to static URLs."""
    jwks_uri = constants.CS_DEFAULT_JWKS_URI
    self._issuer = constants.CS_DEFAULT_ISSUER

    try:
      resp = self._session.get(constants.CS_OIDC_DISCOVERY_URL, timeout=5)
      if resp.status_code == 200:
        data = resp.json()
        jwks_uri = data.get("jwks_uri", jwks_uri)
        self._issuer = data.get("issuer", self._issuer)
    except requests.RequestException:
      logger.warning(
          "OIDC Discovery failed; using fallback configuration.", exc_info=True
      )

    # Initialize PyJWT's JWKS Client with the resolved URI
    self._jwks_client = jwt.PyJWKClient(jwks_uri)

  def validate_token(self, token: str) -> dict[str, Any]:
    """Decodes and validates the OIDC token signature and standard claims.

    Args:
        token: The raw JWT string.

    Returns:
        The decoded claims dictionary.
    """
    try:
      # 1. Fetch the signing key that matches the 'kid' in the token header
      assert self._jwks_client is not None
      signing_key = self._jwks_client.get_signing_key_from_jwt(token)

      # 2. Verify signature, expiration, and issuer
      return jwt.decode(
          token,
          signing_key.key,
          algorithms=["RS256"],
          issuer=self._issuer,
          # We disable strict audience check for Phase 1 as the audience
          # might be generic (e.g., "https://sts.google.com") or specific.
          options={"verify_aud": False},
      )
    except jwt.PyJWTError as e:
      raise exceptions.AttestationVerificationError(
          "OIDC Token validation failed."
      ) from e


class AttestationValidator:
  """Validates attestation evidence against policies and cryptographic bindings."""

  def __init__(
      self,
      policy: attestation_pb2.AttestationPolicy,
      oidc_validator: OIDCTokenValidator | None = None,
  ):
    self._policy = policy
    self._oidc_validator = oidc_validator or OIDCTokenValidator()
    self._owns_oidc_validator = oidc_validator is None

  def close(self) -> None:
    """Closes resources held by the validator."""
    if self._owns_oidc_validator:
      self._oidc_validator.close()

  def validate(
      self, response: attestation_pb2.AttestConnectionResponse, tls_ekm: bytes
  ) -> None:
    """Validates the AttestConnectionResponse from the server.

    Args:
        response: The parsed proto response.
        tls_ekm: The Exported Keying Material from the TLS socket.

    Raises:
        AttestationVerificationError: If validation fails.
        PolicyViolationError: If policy check fails.
    """
    if not response.evidence:
      raise exceptions.AttestationVerificationError(
          "No attestation evidence provided."
      )

    # 1. Extract GCA Bundle
    gca_bundle = next(
        (
            ev.gca_bundle
            for ev in response.evidence
            if ev.verifier_type
            == attestation_pb2.VerifierType.VERIFIER_TYPE_GCA
        ),
        None,
    )

    if not gca_bundle:
      raise exceptions.AttestationVerificationError(
          "required GCA evidence missing."
      )

    if not gca_bundle.attestation_token:
      raise exceptions.AttestationVerificationError(
          "GCA attestation token is empty."
      )

    # 2. Verify OIDC Token Signature (GCA Validation)
    claims = self._oidc_validator.validate_token(gca_bundle.attestation_token)

    # # 3. Policy Enforcement (Workload, Image, Project)
    self._enforce_policy(claims)

    # 4. Verify Instance Key Binding
    # Checks that the Instance Public Key hash is inside the Token's 'eat_nonce'
    instance_pub_bytes = response.instance_public_key.key_bytes
    if not instance_pub_bytes:
      raise exceptions.AttestationVerificationError(
          "Instance public key is missing."
      )

    self._verify_instance_key_binding(claims, instance_pub_bytes)

    # TODO(ashpaw): Add TLS Session binding Verification once server is implemented.

  def _enforce_policy(self, claims: Mapping[str, Any]) -> None:
    """Validates OIDC claims against the configured AttestationPolicy.

    This function follows a "strict validation" model: it only validates fields
    explicitly set in the policy. If a policy field is set but the corresponding
    claim is missing or mismatched, a PolicyViolationError is raised.

    Args:
        claims: The decoded OIDC token claims.

    Raises:
        PolicyViolationError: If policy check fails.
    """
    if not self._policy:
      logger.warning("No attestation policy configured; skipping enforcement.")
      return

    # Extract sub-sections for easier access based on GCA claim structure
    submods = claims.get("submods", {})
    container_claims = submods.get("container", {})
    gce_claims = submods.get("gce", {})

    # 1. Hardware Model Validation
    # GCA Profile: 'hwmodel' claim contains the TEE type
    if self._policy.hw_model != attestation_pb2.HARDWARE_MODEL_UNSPECIFIED:
      token_hw = claims.get("hwmodel")
      # Map Protocol Buffer Enum to GCA string representations
      # Example: HARDWARE_MODEL_SEV -> "GCP_AMD_SEV"
      expected_hw_string = _GCA_STRING_BY_HW_MODEL.get(self._policy.hw_model)

      if token_hw != expected_hw_string:
        raise exceptions.PolicyViolationError(
            f"Hardware model mismatch. Expected {expected_hw_string!r}, got"
            f" {token_hw!r}"
        )

    # 2. Workload Policy Validation
    if self._policy.HasField("workload"):
      workload_policy = self._policy.workload
      # 2a. Image Hash Validation
      if workload_policy.image_hash:
        token_digest = container_claims.get("image_digest")
        if token_digest != workload_policy.image_hash:
          raise exceptions.PolicyViolationError(
              "Workload image hash mismatch. Expected"
              f" {workload_policy.image_hash}, got {token_digest}"
          )

      # 2b. Signing Key Validation (Workload Image Signature)
      # Validates if any of the image signatures were produced by the trusted key
      if workload_policy.signing_key_id:
        signatures = container_claims.get("image_signatures", [])
        # Check if any signature key_id matches the policy
        found_key = any(
            sig.get("key_id") == workload_policy.signing_key_id
            for sig in signatures
        )

        if not found_key:
          raise exceptions.PolicyViolationError(
              "Workload image not signed by trusted key:"
              f" {workload_policy.signing_key_id}"
          )

    # 3. GCE Instance Policy Validation
    # These properties ensure the workload runs in the correct project/zone
    if self._policy.HasField("gce_instance"):
      gce_policy = self._policy.gce_instance

      for field_name in _GCE_POLICY_FIELDS:
        expected_value = getattr(gce_policy, field_name)
        # Only validate if the field is set in the policy
        if not expected_value:
          continue
        actual_value = gce_claims.get(field_name)
        if actual_value != expected_value:
          raise exceptions.PolicyViolationError(
              f"GCE Instance {field_name} mismatch. "
              f"Expected {expected_value}, got {actual_value}"
          )

  def _verify_instance_key_binding(
      self, claims: Mapping[str, Any], pub_key_bytes: bytes
  ) -> None:
    """Verifies that the instance key hash matches the token's eat_nonce.

    Args:
        claims: The decoded OIDC token claims.
        pub_key_bytes: The raw bytes of instance public key.

    Raises:
        AttestationVerificationError: If instance key binding fails.
    """

    # 1. Calculate Hex Digest of the received public key
    expected_nonce_hex = hashlib.sha256(pub_key_bytes).hexdigest()

    # 2. Extract eat_nonce from claims
    eat_nonce = claims.get("eat_nonce")

    if not eat_nonce:
      raise exceptions.AttestationVerificationError(
          "No eat_nonce claim found in OIDC token."
      )

    # Normalize to list
    eat_nonce_list = [eat_nonce] if isinstance(eat_nonce, str) else eat_nonce

    # 3. Check for existence
    if expected_nonce_hex not in eat_nonce_list:
      raise exceptions.AttestationVerificationError(
          f"Instance Key binding failed. Key fingerprint {expected_nonce_hex}"
          f" not found in token nonces {eat_nonce_list!r}."
      )
