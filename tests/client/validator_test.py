"""Tests for the AttestationValidator and OIDCTokenValidator classes."""

import hashlib
from typing import Any
from unittest import mock

from absl.testing import absltest
from absl.testing import parameterized
from prompt_encryption_sdk.client import constants
from prompt_encryption_sdk.client import exceptions
from prompt_encryption_sdk.client import validator
from prompt_encryption_sdk.proto import attestation_pb2
import jwt
import requests


# --- Deterministic Test Constants ---
# Using fixed constants ensures tests are hermetic and repeatable.
_FAKE_IMAGE_HASH = (
    "sha256:67682bda769fae1ccf5183192b8daf37b64cae99c6c3302650f6f8bf5f0f95df"
)
_FAKE_SIGNING_KEY = (
    "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/v"
)
_FAKE_PROJECT = "confidential-ai-2"
_FAKE_ZONE = "us-central1-a"
_FAKE_INSTANCE_NAME = "mhv-test-atls2"
_FAKE_INSTANCE_ID = "2725765997796889912"
_FAKE_PUB_KEY = b"fake-ecdsa-public-key-bytes"


def _get_valid_claims() -> dict[str, Any]:
  """Returns deterministic claims matching the GCA profile."""
  expected_nonce = hashlib.sha256(_FAKE_PUB_KEY).hexdigest()

  return {
      "hwmodel": "GCP_AMD_SEV",
      "eat_nonce": [expected_nonce],
      "submods": {
          "container": {
              "image_digest": _FAKE_IMAGE_HASH,
              "image_signatures": [{"key_id": _FAKE_SIGNING_KEY}],
          },
          "gce": {
              "project_id": _FAKE_PROJECT,
              "zone": _FAKE_ZONE,
              "instance_name": _FAKE_INSTANCE_NAME,
              "instance_id": _FAKE_INSTANCE_ID,
          },
      },
  }


class AttestationValidatorTest(parameterized.TestCase):

  def setUp(self):
    super().setUp()
    self.mock_get = self.enter_context(
        mock.patch.object(requests.Session, "get", autospec=True)
    )
    self.policy = attestation_pb2.AttestationPolicy()
    self.validator = validator.AttestationValidator(self.policy)

  # --- 1. Instance Key Binding Tests ---

  def test_verify_instance_key_binding_success(self):
    """Tests that a matching public key hash passes validation."""
    claims = _get_valid_claims()
    self.validator._verify_instance_key_binding(claims, _FAKE_PUB_KEY)

  def test_verify_instance_key_binding_single_string_nonce(self):
    """Tests that validator handles 'eat_nonce' as a string instead of a list."""
    expected_nonce = hashlib.sha256(_FAKE_PUB_KEY).hexdigest()
    claims = {"eat_nonce": expected_nonce}
    self.validator._verify_instance_key_binding(claims, _FAKE_PUB_KEY)

  def test_verify_instance_key_binding_fails_on_mismatch(self):
    """Tests that mismatched public key triggers an error."""
    claims = _get_valid_claims()
    wrong_key = b"different-public-key-material"
    with self.assertRaisesRegex(
        exceptions.AttestationVerificationError, "Instance Key binding failed"
    ):
      self.validator._verify_instance_key_binding(claims, wrong_key)

  def test_verify_instance_key_binding_fails_on_empty_nonce(self):
    """Tests that missing eat_nonce claim triggers an error."""
    claims = {}
    with self.assertRaisesRegex(
        exceptions.AttestationVerificationError,
        "No eat_nonce claim found in OIDC token.",
    ):
      self.validator._verify_instance_key_binding(claims, _FAKE_PUB_KEY)

  def test_verify_instance_key_binding_fails_on_none_nonce(self):
    """Tests that eat_nonce claim being None triggers an error."""
    claims = {"eat_nonce": None}
    with self.assertRaisesRegex(
        exceptions.AttestationVerificationError,
        "No eat_nonce claim found in OIDC token.",
    ):
      self.validator._verify_instance_key_binding(claims, _FAKE_PUB_KEY)

  # --- 2. Policy Enforcement Tests ---

  @parameterized.named_parameters(
      (
          "hw_model_mismatch",
          attestation_pb2.AttestationPolicy(
              hw_model=attestation_pb2.HARDWARE_MODEL_TDX
          ),
          "Hardware model mismatch",
      ),
      (
          "image_hash_mismatch",
          attestation_pb2.AttestationPolicy(
              workload=attestation_pb2.WorkloadPolicy(image_hash="wrong_hash")
          ),
          "Workload image hash mismatch",
      ),
      (
          "signing_key_missing",
          attestation_pb2.AttestationPolicy(
              workload=attestation_pb2.WorkloadPolicy(
                  signing_key_id="other_key"
              )
          ),
          "Workload image not signed by trusted key",
      ),
      (
          "project_id_mismatch",
          attestation_pb2.AttestationPolicy(
              gce_instance=attestation_pb2.GceInstancePolicy(
                  project_id="wrong-proj"
              )
          ),
          "GCE Instance project_id mismatch",
      ),
      (
          "zone_mismatch",
          attestation_pb2.AttestationPolicy(
              gce_instance=attestation_pb2.GceInstancePolicy(
                  zone="europe-west1-b"
              )
          ),
          "GCE Instance zone mismatch",
      ),
  )
  def test_enforce_policy_violations(self, policy, expected_error):
    """Tests that policy mismatches trigger PolicyViolationError."""
    self.validator._policy = policy
    claims = _get_valid_claims()

    with self.assertRaisesRegex(
        exceptions.PolicyViolationError, expected_error
    ):
      self.validator._enforce_policy(claims)

  def test_enforce_policy_optional_fields_ignored(self):
    """Ensures fields NOT set in policy are NOT validated."""
    self.validator._policy = attestation_pb2.AttestationPolicy(
        hw_model=attestation_pb2.HARDWARE_MODEL_SEV
    )

    claims = _get_valid_claims()
    claims["submods"]["gce"]["project_id"] = "different-untracked-project"

    # Should pass because project_id is not in the active policy.
    self.validator._enforce_policy(claims)

  def test_enforce_policy_missing_claim_fails(self):
    """Tests that a missing claim expected by the policy raises an error."""
    policy = attestation_pb2.AttestationPolicy(
        workload=attestation_pb2.WorkloadPolicy(image_hash=_FAKE_IMAGE_HASH)
    )
    self.validator._policy = policy
    claims = _get_valid_claims()
    # Remove the claim expected by the policy
    del claims["submods"]["container"]["image_digest"]

    with self.assertRaisesRegex(
        exceptions.PolicyViolationError,
        f"Workload image hash mismatch. Expected {_FAKE_IMAGE_HASH}, got None",
    ):
      self.validator._enforce_policy(claims)

  # --- 3. Main Validation Orchestration Tests ---

  def test_validate_full_success(self):
    """Tests the full validation flow including token extraction."""
    mock_oidc = self.enter_context(
        mock.patch.object(
            validator.OIDCTokenValidator, "validate_token", autospec=True
        )
    )
    mock_oidc.return_value = _get_valid_claims()

    response = attestation_pb2.AttestConnectionResponse()
    response.instance_public_key.key_bytes = _FAKE_PUB_KEY
    evidence = response.evidence.add(
        verifier_type=attestation_pb2.VerifierType.VERIFIER_TYPE_GCA,
    )
    evidence.gca_bundle.attestation_token = "valid.jwt.payload"

    self.validator.validate(response, tls_ekm=b"fake_ekm_material")
    mock_oidc.assert_called_once_with(mock.ANY, "valid.jwt.payload")

  def test_validate_no_evidence_fails(self):
    """Tests failure when no attestation evidence is provided."""
    response = attestation_pb2.AttestConnectionResponse()
    with self.assertRaisesRegex(
        exceptions.AttestationVerificationError,
        "No attestation evidence provided",
    ):
      self.validator.validate(response, tls_ekm=b"")

  def test_validate_missing_gca_evidence_fails(self):
    """Tests failure when GCA evidence is missing."""
    response = attestation_pb2.AttestConnectionResponse()
    response.evidence.add(
        verifier_type=attestation_pb2.VerifierType.VERIFIER_TYPE_UNSPECIFIED
    )
    with self.assertRaisesRegex(
        exceptions.AttestationVerificationError, "required GCA evidence missing"
    ):
      self.validator.validate(response, tls_ekm=b"")

  def test_validate_empty_attestation_token_fails(self):
    """Tests failure when GCA attestation token is empty."""
    response = attestation_pb2.AttestConnectionResponse()
    response.evidence.add(
        verifier_type=attestation_pb2.VerifierType.VERIFIER_TYPE_GCA
    )
    # gca_bundle exists but attestation_token is empty
    with self.assertRaisesRegex(
        exceptions.AttestationVerificationError,
        "GCA attestation token is empty",
    ):
      self.validator.validate(response, tls_ekm=b"")

  def test_validate_missing_instance_public_key_fails(self):
    """Tests failure when instance public key is missing."""
    with mock.patch.object(
        self.validator._oidc_validator,
        "validate_token",
        return_value=_get_valid_claims(),
        autospec=True,
    ):
      response = attestation_pb2.AttestConnectionResponse()
      evidence = response.evidence.add(
          verifier_type=attestation_pb2.VerifierType.VERIFIER_TYPE_GCA,
      )
      evidence.gca_bundle.attestation_token = "valid.jwt.payload"
      # instance_public_key is missing
      with self.assertRaisesRegex(
          exceptions.AttestationVerificationError,
          "Instance public key is missing",
      ):
        self.validator.validate(response, tls_ekm=b"")

  def test_validate_uses_passed_oidc_validator(self):
    """Tests that validate() uses the passed oidc_validator instance."""
    mock_oidc_validator = mock.create_autospec(validator.OIDCTokenValidator)
    mock_oidc_validator.validate_token.return_value = _get_valid_claims()
    av = validator.AttestationValidator(
        self.policy, oidc_validator=mock_oidc_validator
    )

    response = attestation_pb2.AttestConnectionResponse()
    response.instance_public_key.key_bytes = _FAKE_PUB_KEY
    evidence = response.evidence.add(
        verifier_type=attestation_pb2.VerifierType.VERIFIER_TYPE_GCA,
    )
    evidence.gca_bundle.attestation_token = "valid.jwt.payload"

    av.validate(response, tls_ekm=b"fake_ekm_material")
    mock_oidc_validator.validate_token.assert_called_once_with(
        "valid.jwt.payload"
    )

  # --- 4. Resource Management Tests ---

  def test_close_with_owned_oidc_validator_closes_oidc(self):
    """Tests AttestationValidator.close() closes OIDC validator if it owns it."""
    with mock.patch.object(
        validator, "OIDCTokenValidator", autospec=True
    ) as mock_cls:
      av = validator.AttestationValidator(self.policy)
      av.close()
      mock_cls.return_value.close.assert_called_once()

  def test_close_with_passed_oidc_validator_does_not_close_oidc(self):
    """Tests AttestationValidator.close() does not close OIDC validator if it doesn't own it."""
    mock_oidc_validator = mock.create_autospec(validator.OIDCTokenValidator)
    av = validator.AttestationValidator(
        self.policy, oidc_validator=mock_oidc_validator
    )
    av.close()
    mock_oidc_validator.close.assert_not_called()

  def test_validate_calls_enforce_policy_and_key_binding(self):
    """Tests that validate() calls _enforce_policy and _verify_instance_key_binding."""
    mock_oidc = self.enter_context(
        mock.patch.object(
            validator.OIDCTokenValidator, "validate_token", autospec=True
        )
    )
    claims = _get_valid_claims()
    mock_oidc.return_value = claims

    # We wrap the existing methods in mocks so we can verify they were called
    # while still allowing them to execute their logic.
    with mock.patch.object(
        self.validator, "_enforce_policy", wraps=self.validator._enforce_policy
    ) as spy_policy:
      with mock.patch.object(
          self.validator,
          "_verify_instance_key_binding",
          wraps=self.validator._verify_instance_key_binding,
      ) as spy_binding:

        response = attestation_pb2.AttestConnectionResponse()
        response.instance_public_key.key_bytes = _FAKE_PUB_KEY
        evidence = response.evidence.add(
            verifier_type=attestation_pb2.VerifierType.VERIFIER_TYPE_GCA,
        )
        evidence.gca_bundle.attestation_token = "valid.jwt.payload"

        self.validator.validate(response, tls_ekm=b"fake_ekm_material")

        # If Line 142 is removed, this fails:
        spy_policy.assert_called_once_with(claims)
        # If Line 150 is removed, this fails:
        spy_binding.assert_called_once_with(claims, _FAKE_PUB_KEY)


class OIDCTokenValidatorTest(parameterized.TestCase):

  def setUp(self):
    super().setUp()
    self.mock_get = self.enter_context(
        mock.patch.object(requests.Session, "get", autospec=True)
    )

  def test_validate_token_success_and_options(self):
    """Tests that validate_token succeeds and passes correct options to jwt.decode."""
    self.mock_get.return_value.status_code = 200
    self.mock_get.return_value.json.return_value = {
        "issuer": constants.CS_DEFAULT_ISSUER,
        "jwks_uri": constants.CS_DEFAULT_JWKS_URI,
    }
    mock_key = mock.Mock()
    mock_jwk_client = self.enter_context(
        mock.patch.object(jwt, "PyJWKClient", autospec=True)
    )
    mock_jwk_client.return_value.get_signing_key_from_jwt.return_value = (
        mock_key
    )
    mock_decode = self.enter_context(
        mock.patch.object(jwt, "decode", autospec=True)
    )
    mock_decode.return_value = {"claim": "value"}

    v = validator.OIDCTokenValidator()
    token = "some.valid.token"
    result = v.validate_token(token)

    self.assertEqual(result, {"claim": "value"})
    mock_decode.assert_called_once_with(
        token,
        mock_key.key,
        algorithms=["RS256"],
        issuer=constants.CS_DEFAULT_ISSUER,
        options={"verify_aud": False},
    )

  def test_oidc_discovery_fallback_on_network_error(self):
    """Tests fallback to defaults if OIDC discovery fails."""
    self.mock_get.side_effect = requests.RequestException("Timeout")

    v = validator.OIDCTokenValidator()
    self.assertEqual(v._issuer, constants.CS_DEFAULT_ISSUER)

  def test_validate_token_failure(self):
    """Tests that JWT decode errors are correctly caught and wrapped."""
    self.enter_context(
        mock.patch.object(
            jwt.PyJWKClient, "get_signing_key_from_jwt", autospec=True
        )
    )
    self.enter_context(
        mock.patch.object(
            jwt,
            "decode",
            side_effect=jwt.InvalidTokenError("Bad Signature"),
            autospec=True,
        )
    )

    v = validator.OIDCTokenValidator()
    v._jwks_client = mock.Mock()

    with self.assertRaisesRegex(
        exceptions.AttestationVerificationError, "OIDC Token validation failed"
    ):
      v.validate_token("some.invalid.token")

  def test_oidc_token_validator_close_closes_session(self):
    mock_session = mock.create_autospec(requests.Session)
    oidc_validator = validator.OIDCTokenValidator(session=mock_session)
    oidc_validator.close()
    mock_session.close.assert_called_once()


if __name__ == "__main__":
  absltest.main()
