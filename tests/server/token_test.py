# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Tests for server.token."""

import hashlib
import http.client
import os
import pathlib
import random
import socket
from unittest import mock

from absl.testing import absltest
from prompt_encryption_sdk.server import keys
from prompt_encryption_sdk.server import token


class TokenTest(absltest.TestCase):

  def test_get_custom_token_bytes_success(self):
    mock_conn = mock.create_autospec(
        token.UnixSocketConnection, instance=True, spec_set=True
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
        token.UnixSocketConnection, instance=False, spec_set=True
    )
    mock_connection_factory.return_value = mock_conn
    mock.seal(mock_connection_factory)

    token_bytes = token.get_custom_token_bytes(
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
      token.get_custom_token_bytes(
          connection_factory=mock_connection_factory, audience="test_audience"
      )

  @mock.patch.object(socket, "socket", autospec=True)
  def test_unix_socket_connection_connect(self, mock_socket):
    socket_path = "/test/socket"
    with token.UnixSocketConnection(pathlib.Path(socket_path)) as conn:
      conn.connect()
      mock_socket.assert_called_once_with(socket.AF_UNIX, socket.SOCK_STREAM)
      conn.sock.connect.assert_called_once_with(socket_path)


class TokenManagerTest(absltest.TestCase):

  def setUp(self):
    super().setUp()
    self.mock_key_manager = mock.create_autospec(
        keys.KeyManager, instance=True, spec_set=True
    )
    self.temp_dir = self.create_tempdir()
    self.attestation_token_path = pathlib.Path(
        os.path.join(self.temp_dir.full_path, "attestation_token.txt")
    )
    self.seeded_rng = random.Random(24)

  @mock.patch.object(token, "get_custom_token_bytes", autospec=True)
  def test_refresh(self, mock_get_custom_token_bytes):
    public_key = b"test_public_key"
    public_key_fingerprint = hashlib.sha256(public_key).hexdigest()
    self.mock_key_manager.get_current_public_key.return_value = public_key
    mock_get_custom_token_bytes.return_value = b"test_token"

    token_manager = token.TokenManager(
        key_manager=self.mock_key_manager,
        attestation_token_path=self.attestation_token_path,
        rng=self.seeded_rng,
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
    token_manager = token.TokenManager(key_manager=self.mock_key_manager)
    self.assertEqual(token_manager.get_public_key(), public_key)
    self.mock_key_manager.get_current_public_key.assert_called_once()

  def test_get_attestation_token(self):
    attestation_token = b"test_token"
    with open(self.attestation_token_path, "wb") as f:
      f.write(attestation_token)
    token_manager = token.TokenManager(
        key_manager=self.mock_key_manager,
        attestation_token_path=self.attestation_token_path,
    )
    self.assertEqual(token_manager.get_attestation_token(), attestation_token)

  def test_get_attestation_token_not_found(self):
    token_manager = token.TokenManager(
        key_manager=self.mock_key_manager,
        attestation_token_path="/nonexistent/path",
    )
    self.assertEqual(token_manager.get_attestation_token(), b"")


if __name__ == "__main__":
  absltest.main()
