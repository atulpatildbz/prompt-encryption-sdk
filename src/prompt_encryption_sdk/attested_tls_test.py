"""Tests for attested_tls."""

import hashlib
import http.client
import os
import pathlib
import random
import socket
from unittest import mock

from absl.testing import absltest
from attested_confidential_inference import attested_tls
from attested_confidential_inference.proto import attestation_pb2
from cryptography.hazmat.primitives.asymmetric import ec

from google3.net.proto2.contrib.pyutil import compare


class AttestedTlsTest(absltest.TestCase):

  def test_write_file_atomically(self):
    temp_dir = self.create_tempdir()
    file_path = temp_dir.create_file("test.txt").full_path
    attested_tls._write_file(pathlib.Path(file_path), b"new_content", 0o644)
    with open(file_path, "rb") as f:
      self.assertEqual(f.read(), b"new_content")

  @mock.patch.object(os, "replace", autospec=True)
  @mock.patch.object(os, "fdopen")
  @mock.patch.object(os, "open", autospec=True)
  @mock.patch.object(attested_tls.ec, "generate_private_key", autospec=True)
  def test_key_manager_generate_key_pair(
      self,
      mock_generate_private_key,
      mock_os_open,
      mock_os_fdopen,
      mock_os_replace,
  ):
    mock_private_key = mock.create_autospec(
        ec.EllipticCurvePrivateKey, instance=True, spec_set=True
    )
    mock_public_key = mock.create_autospec(
        ec.EllipticCurvePublicKey, instance=True, spec_set=True
    )
    mock_private_key.public_key.return_value = mock_public_key
    mock_generate_private_key.return_value = mock_private_key

    pem_public_bytes = b"pem_public_bytes"
    mock_public_key.public_bytes.return_value = pem_public_bytes
    pem_private_bytes = b"pem_private_bytes"
    mock_private_key.private_bytes.return_value = pem_private_bytes

    temp_dir = self.create_tempdir()
    private_key_path = pathlib.Path(temp_dir.full_path, "private.pem")
    public_key_path = pathlib.Path(temp_dir.full_path, "public.pem")

    mock_private_key_fd = 123
    mock_public_key_fd = 456
    mock_os_open.side_effect = [mock_private_key_fd, mock_public_key_fd]

    mock_private_key_file = mock.mock_open()()
    mock_public_key_file = mock.mock_open()()
    mock_os_fdopen.side_effect = [mock_private_key_file, mock_public_key_file]

    key_manager = attested_tls.KeyManager(
        private_key_path=private_key_path, public_key_path=public_key_path
    )
    public_key = key_manager.generate_key_pair()

    with self.subTest(name="PublicKeyReturned"):
      self.assertEqual(public_key, pem_public_bytes)

    with self.subTest(name="PrivateKeyGenerated"):
      mock_generate_private_key.assert_called_once()

    with self.subTest(name="KeysWritten"):
      private_key_temp_path = private_key_path.with_name(
          private_key_path.name + ".tmp"
      )
      public_key_temp_path = public_key_path.with_name(
          public_key_path.name + ".tmp"
      )
      mock_os_open.assert_has_calls([
          mock.call(
              private_key_temp_path,
              os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
              0o600,
          ),
          mock.call(
              public_key_temp_path,
              os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
              0o644,
          ),
      ])
      mock_os_replace.assert_has_calls([
          mock.call(private_key_temp_path, private_key_path),
          mock.call(public_key_temp_path, public_key_path),
      ])
      mock_os_fdopen.assert_has_calls([
          mock.call(mock_private_key_fd, "wb"),
          mock.call(mock_public_key_fd, "wb"),
      ])
      mock_private_key_file.write.assert_called_once_with(pem_private_bytes)
      mock_public_key_file.write.assert_called_once_with(pem_public_bytes)

  def test_key_manager_get_current_public_key(self):
    public_key_bytes = b"test_public_key"
    temp_dir = self.create_tempdir()
    public_key_path = pathlib.Path(temp_dir.full_path, "public.pem")
    with open(public_key_path, "wb") as f:
      f.write(public_key_bytes)

    key_manager = attested_tls.KeyManager(public_key_path=public_key_path)
    self.assertEqual(key_manager.get_current_public_key(), public_key_bytes)

  def test_get_custom_token_bytes_success(self):
    mock_conn = mock.create_autospec(
        attested_tls.UnixSocketConnection, instance=True, spec_set=True
    )
    mock_conn.__enter__.return_value = mock_conn
    mock_conn.__exit__.return_value = None

    mock_response = mock.create_autospec(
        http.client.HTTPResponse, instance=True, spec_set=False
    )
    mock_response.status = 200
    mock_response.read.return_value = b"test_token"
    mock_conn.getresponse.return_value = mock_response
    mock.seal(mock_response)
    mock.seal(mock_conn)
    mock_connection_factory = mock.create_autospec(
        attested_tls.UnixSocketConnection, instance=False, spec_set=True
    )
    mock_connection_factory.return_value = mock_conn
    mock.seal(mock_connection_factory)

    token_bytes = attested_tls.get_custom_token_bytes(
        socket_path=pathlib.Path("test_socket"),
        connection_factory=mock_connection_factory,
        audience="test_audience",
    )

    self.assertEqual(token_bytes, b"test_token")
    mock_connection_factory.assert_called_once_with(pathlib.Path("test_socket"))
    mock_conn.request.assert_called_once_with(
        "POST",
        "/v1/token",
        body='{"audience": "test_audience"}'.encode("utf-8"),
        headers={"Content-Type": "application/json"},
    )

  def test_get_custom_token_bytes_error(self):
    mock_conn = mock.MagicMock()
    mock_conn.__enter__.return_value = mock_conn

    mock_response = mock.MagicMock()
    mock_response.status = 400
    mock_response.reason = "Bad Request"
    mock_conn.getresponse.return_value = mock_response
    mock_connection_factory = mock.MagicMock(return_value=mock_conn)

    with self.assertRaisesRegex(RuntimeError, "HTTP Error 400: Bad Request"):
      attested_tls.get_custom_token_bytes(
          connection_factory=mock_connection_factory, audience="test_audience"
      )

  @mock.patch.object(socket, "socket", autospec=True)
  def test_unix_socket_connection_connect(self, mock_socket):
    socket_path = "/test/socket"
    with attested_tls.UnixSocketConnection(pathlib.Path(socket_path)) as conn:
      conn.connect()
      mock_socket.assert_called_once_with(socket.AF_UNIX, socket.SOCK_STREAM)
      conn.sock.connect.assert_called_once_with(socket_path)

  def test_calculate_fingerprint(self):
    public_key = b"test_public_key"
    expected_fingerprint = hashlib.sha256(public_key).hexdigest()
    self.assertEqual(
        attested_tls.calculate_fingerprint(public_key), expected_fingerprint
    )


class TokenManagerTest(absltest.TestCase):

  def setUp(self):
    super().setUp()
    self.mock_key_manager = mock.create_autospec(
        attested_tls.KeyManager, instance=True, spec_set=True
    )
    self.temp_dir = self.create_tempdir()
    self.attestation_token_path = pathlib.Path(
        os.path.join(self.temp_dir.full_path, "attestation_token.txt")
    )
    self.seeded_random = random.Random(42)

  @mock.patch.object(attested_tls, "get_custom_token_bytes", autospec=True)
  def test_refresh(self, mock_get_custom_token_bytes):
    public_key = b"test_public_key"
    public_key_fingerprint = hashlib.sha256(public_key).hexdigest()
    self.mock_key_manager.get_current_public_key.return_value = public_key
    mock_get_custom_token_bytes.return_value = b"test_token"

    token_manager = attested_tls.TokenManager(
        key_manager=self.mock_key_manager,
        attestation_token_path=self.attestation_token_path,
        rng=self.seeded_random,
    )
    token_manager.refresh()

    with self.subTest(name="KeyPairGenerated"):
      self.mock_key_manager.generate_key_pair.assert_called_once()

    with self.subTest(name="PublicKeyRetrieved"):
      self.mock_key_manager.get_current_public_key.assert_called_once()

    with self.subTest(name="CustomTokenRequested"):
      mock_get_custom_token_bytes.assert_called_once_with(
          audience="https://sts.google.com",
          token_type="OIDC",
          nonces=[public_key_fingerprint],
      )

    with self.subTest(name="AttestationTokenWritten"):
      with open(self.attestation_token_path, "rb") as f:
        self.assertEqual(f.read(), b"test_token")

  def test_get_public_key(self):
    public_key = b"test_public_key"
    self.mock_key_manager.get_current_public_key.return_value = public_key
    token_manager = attested_tls.TokenManager(
        key_manager=self.mock_key_manager,
        rng=self.seeded_random,
    )
    self.assertEqual(token_manager.get_public_key(), public_key)
    self.mock_key_manager.get_current_public_key.assert_called_once()

  def test_get_attestation_token(self):
    attestation_token = b"test_token"
    with open(self.attestation_token_path, "wb") as f:
      f.write(attestation_token)
    token_manager = attested_tls.TokenManager(
        key_manager=self.mock_key_manager,
        attestation_token_path=self.attestation_token_path,
    )
    self.assertEqual(token_manager.get_attestation_token(), attestation_token)

  def test_get_attestation_token_not_found(self):
    token_manager = attested_tls.TokenManager(
        key_manager=self.mock_key_manager,
        attestation_token_path="/nonexistent/path",
    )
    self.assertEqual(token_manager.get_attestation_token(), b"")

  def test_get_identity_snapshot(self):
    public_key = b"test_public_key"
    attestation_token = b"test_token"
    self.mock_key_manager.get_current_public_key.return_value = public_key
    with open(self.attestation_token_path, "wb") as f:
      f.write(attestation_token)
    token_manager = attested_tls.TokenManager(
        key_manager=self.mock_key_manager,
        attestation_token_path=self.attestation_token_path,
    )
    self.assertEqual(
        token_manager.get_identity_snapshot(), (public_key, attestation_token)
    )


class AttestedTlsImplTest(absltest.TestCase, compare.Proto2Assertions):

  def test_attest_connection(self):
    mock_token_manager = mock.create_autospec(
        attested_tls.TokenManager, instance=True, spec_set=True
    )
    public_key = b"test_public_key"
    attestation_token = "test_attestation_token"
    mock_token_manager.get_identity_snapshot.return_value = (
        public_key,
        attestation_token.encode("utf-8"),
    )

    attested_tls_instance = attested_tls.AttestedTLS(
        token_manager=mock_token_manager
    )

    request = attested_tls.attestation_pb2.AttestConnectionRequest(
        required_verifier_type=[
            attested_tls.attestation_pb2.VerifierType.VERIFIER_TYPE_GCA
        ]
    )

    response = attested_tls_instance.attest_connection(request)
    expected_response = attested_tls.attestation_pb2.AttestConnectionResponse(
        evidence=[
            attestation_pb2.AttestationEvidence(
                verifier_type=attestation_pb2.VerifierType.VERIFIER_TYPE_GCA,
                gca_bundle=attestation_pb2.GcaTrustBundle(
                    attestation_token=attestation_token
                ),
            ),
        ],
        instance_public_key=attestation_pb2.EcdsaP256PublicKey(
            key_bytes=public_key
        ),
    )
    self.assertProto2Equal(response, expected_response)

  def test_attest_connection_no_verifier(self):
    mock_token_manager = mock.create_autospec(
        attested_tls.TokenManager, instance=True, spec_set=True
    )
    attested_tls_instance = attested_tls.AttestedTLS(
        token_manager=mock_token_manager
    )
    request = attested_tls.attestation_pb2.AttestConnectionRequest()
    with self.assertRaisesRegex(
        ValueError, "At least one required_verifier_type must be specified"
    ):
      attested_tls_instance.attest_connection(request)

  def test_attest_connection_unsupported_verifier(self):
    mock_token_manager = mock.create_autospec(
        attested_tls.TokenManager, instance=True, spec_set=True
    )
    attested_tls_instance = attested_tls.AttestedTLS(
        token_manager=mock_token_manager
    )
    request = attested_tls.attestation_pb2.AttestConnectionRequest(
        required_verifier_type=[
            attested_tls.attestation_pb2.VerifierType.VERIFIER_TYPE_UNSPECIFIED
        ]
    )
    with self.assertRaisesRegex(
        ValueError, "Unsupported verifier types requested"
    ):
      attested_tls_instance.attest_connection(request)


if __name__ == "__main__":
  absltest.main()
