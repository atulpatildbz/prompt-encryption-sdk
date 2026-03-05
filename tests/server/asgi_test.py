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

"""Tests for server.asgi."""

import asyncio
import json
from unittest import mock

from absl.testing import absltest
from prompt_encryption_sdk.proto import attestation_pb2
from prompt_encryption_sdk.server import asgi
from prompt_encryption_sdk.server import attestation
from prompt_encryption_sdk.server import keys
from prompt_encryption_sdk.server import token
from google.protobuf import json_format
import uvicorn
from uvicorn.protocols.http import h11_impl


class MiddlewareTest(absltest.TestCase):

  def setUp(self):
    super().setUp()
    self.mock_attested_tls = mock.create_autospec(
        attestation.AttestedTLS, instance=True
    )
    self.app = mock.AsyncMock()
    self.mw = asgi.PromptEncryptionASGIMiddleware(self.app, self.mock_attested_tls)
    self.send = mock.AsyncMock()
    self.ssl_obj = mock.MagicMock()

  def test_call_other_path(self):
    async def run():
      scope = {"type": "http", "path": "/other"}
      receive = mock.AsyncMock()
      await self.mw(scope, receive, self.send)
      self.app.assert_called_once_with(scope, receive, self.send)

    asyncio.run(run())

  def test_handle_attestation_success(self):
    async def run():
      scope = {
          "type": "http",
          "path": "/_attest-connection",
          "method": "POST",
          "headers": [],
          "extensions": {"tls_socket": self.ssl_obj},
      }
      request_proto = attestation_pb2.AttestConnectionRequest(
          required_verifier_type=[
              attestation_pb2.VerifierType.VERIFIER_TYPE_GCA
          ]
      )
      body = json_format.MessageToJson(request_proto).encode("utf-8")

      async def receive():
        return {"type": "http.request", "body": body, "more_body": False}

      response_proto = attestation_pb2.AttestConnectionResponse(
          instance_public_key=attestation_pb2.EcdsaP256PublicKey(
              key_bytes=b"test_public_key"
          )
      )
      self.mock_attested_tls.attest_connection.return_value = response_proto

      await self.mw(scope, receive, self.send)

      self.mock_attested_tls.attest_connection.assert_called_once_with(
          request_proto,
          ssl_obj=self.ssl_obj,
          label="EXPORTER-Prompt-Encryption-SDK",
      )
      calls = self.send.call_args_list
      self.assertEqual(calls[0].args[0]["type"], "http.response.start")
      self.assertEqual(calls[0].args[0]["status"], 200)
      self.assertEqual(calls[1].args[0]["type"], "http.response.body")
      response_dict = json_format.MessageToDict(response_proto)
      self.assertEqual(
          json.loads(calls[1].args[0]["body"]),
          response_dict,
      )

    asyncio.run(run())

  def test_handle_attestation_success_with_label(self):
    async def run():
      scope = {
          "type": "http",
          "path": "/_attest-connection",
          "method": "POST",
          "headers": [],
          "extensions": {"tls_socket": self.ssl_obj},
      }
      request_dict = {
          "requiredVerifierType": ["VERIFIER_TYPE_GCA"],
          "label": "my-custom-label",
      }
      body = json.dumps(request_dict).encode("utf-8")

      request_proto = attestation_pb2.AttestConnectionRequest(
          required_verifier_type=[
              attestation_pb2.VerifierType.VERIFIER_TYPE_GCA
          ]
      )

      async def receive():
        return {"type": "http.request", "body": body, "more_body": False}

      response_proto = attestation_pb2.AttestConnectionResponse(
          instance_public_key=attestation_pb2.EcdsaP256PublicKey(
              key_bytes=b"test_public_key"
          )
      )
      self.mock_attested_tls.attest_connection.return_value = response_proto

      await self.mw(scope, receive, self.send)

      self.mock_attested_tls.attest_connection.assert_called_once_with(
          request_proto, ssl_obj=self.ssl_obj, label="my-custom-label"
      )
      calls = self.send.call_args_list
      self.assertEqual(calls[0].args[0]["type"], "http.response.start")
      self.assertEqual(calls[0].args[0]["status"], 200)
      self.assertEqual(calls[1].args[0]["type"], "http.response.body")
      response_dict = json_format.MessageToDict(response_proto)
      self.assertEqual(
          json.loads(calls[1].args[0]["body"]),
          response_dict,
      )

    asyncio.run(run())

  def test_handle_attestation_no_ssl_obj(self):
    async def run():
      scope = {
          "type": "http",
          "path": "/_attest-connection",
          "method": "POST",
          "headers": [],
          "extensions": {},
      }
      request_proto = attestation_pb2.AttestConnectionRequest()
      body = json_format.MessageToJson(request_proto).encode("utf-8")

      async def receive():
        return {"type": "http.request", "body": body, "more_body": False}

      await self.mw(scope, receive, self.send)

      self.mock_attested_tls.attest_connection.assert_not_called()
      calls = self.send.call_args_list
      self.assertEqual(calls[0].args[0]["type"], "http.response.start")
      self.assertEqual(calls[0].args[0]["status"], 500)
      self.assertEqual(calls[1].args[0]["type"], "http.response.body")
      body_dict = json.loads(calls[1].args[0]["body"])
      self.assertEqual(
          body_dict,
          {
              "error": (
                  "An internal server error occurred: RuntimeError('TLS Socket"
                  " not found.')"
              )
          },
      )

    asyncio.run(run())

  def test_handle_attestation_invalid_json_body(self):
    async def run():
      scope = {
          "type": "http",
          "path": "/_attest-connection",
          "method": "POST",
          "headers": [],
          "extensions": {"tls_socket": self.ssl_obj},
      }
      body = b"invalid json"

      async def receive():
        return {"type": "http.request", "body": body, "more_body": False}

      await self.mw(scope, receive, self.send)

      self.mock_attested_tls.attest_connection.assert_not_called()
      calls = self.send.call_args_list
      self.assertEqual(calls[0].args[0]["type"], "http.response.start")
      self.assertEqual(calls[0].args[0]["status"], 400)
      self.assertEqual(calls[1].args[0]["type"], "http.response.body")
      body_dict = json.loads(calls[1].args[0]["body"])
      self.assertIn("An internal server error occurred", body_dict["error"])

    asyncio.run(run())

  def test_handle_attestation_undecodable_body(self):
    async def run():
      scope = {
          "type": "http",
          "path": "/_attest-connection",
          "method": "POST",
          "headers": [],
          "extensions": {"tls_socket": self.ssl_obj},
      }
      body = b"\x80abc"

      async def receive():
        return {"type": "http.request", "body": body, "more_body": False}

      await self.mw(scope, receive, self.send)

      self.mock_attested_tls.attest_connection.assert_not_called()
      calls = self.send.call_args_list
      self.assertEqual(calls[0].args[0]["type"], "http.response.start")
      self.assertEqual(calls[0].args[0]["status"], 500)
      self.assertEqual(calls[1].args[0]["type"], "http.response.body")
      body_dict = json.loads(calls[1].args[0]["body"])
      self.assertIn("An internal server error occurred", body_dict["error"])

    asyncio.run(run())

  def test_handle_attestation_proto_parse_error(self):
    async def run():
      scope = {
          "type": "http",
          "path": "/_attest-connection",
          "method": "POST",
          "headers": [],
          "extensions": {"tls_socket": self.ssl_obj},
      }
      body = b'{"requiredVerifierType": 1}'

      async def receive():
        return {"type": "http.request", "body": body, "more_body": False}

      await self.mw(scope, receive, self.send)

      self.mock_attested_tls.attest_connection.assert_not_called()
      calls = self.send.call_args_list
      self.assertEqual(calls[0].args[0]["type"], "http.response.start")
      self.assertEqual(calls[0].args[0]["status"], 400)
      self.assertEqual(calls[1].args[0]["type"], "http.response.body")
      body_dict = json.loads(calls[1].args[0]["body"])
      self.assertIn("An internal server error occurred", body_dict["error"])

    asyncio.run(run())

  def test_attest_connection_internal_error(self):
    async def run():
      scope = {
          "type": "http",
          "path": "/_attest-connection",
          "method": "POST",
          "headers": [],
          "extensions": {"tls_socket": self.ssl_obj},
      }
      request_proto = attestation_pb2.AttestConnectionRequest()
      body = json_format.MessageToJson(request_proto).encode("utf-8")

      async def receive():
        return {"type": "http.request", "body": body, "more_body": False}

      self.mock_attested_tls.attest_connection.side_effect = ValueError(
          "test error"
      )

      await self.mw(scope, receive, self.send)

      self.mock_attested_tls.attest_connection.assert_called_once()
      calls = self.send.call_args_list
      self.assertEqual(calls[0].args[0]["type"], "http.response.start")
      self.assertEqual(calls[0].args[0]["status"], 500)
      self.assertEqual(calls[1].args[0]["type"], "http.response.body")
      body_dict = json.loads(calls[1].args[0]["body"])
      self.assertEqual(
          body_dict,
          {
              "error": (
                  "An internal server error occurred: ValueError('test error')"
              )
          },
      )

    asyncio.run(run())

  @mock.patch.object(asgi.uvicorn, "run", autospec=True)
  @mock.patch.object(keys, "KeyManager", autospec=True)
  @mock.patch.object(token, "TokenManager", autospec=True)
  @mock.patch.object(attestation, "AttestedTLS", autospec=True)
  def test_run_uvicorn_app_defaults(
      self,
      mock_attested_tls_cls,
      mock_token_manager_cls,
      mock_key_manager_cls,
      mock_uvicorn_run,
  ):
    mock_app = mock.MagicMock()
    asgi.run_uvicorn_app(mock_app, host="localhost", port=8000)

    mock_key_manager_cls.assert_called_once()
    mock_token_manager_cls.assert_called_once_with(
        key_manager=mock_key_manager_cls.return_value
    )
    mock_token_manager_cls.return_value.__enter__.assert_called_once()
    mock_attested_tls_cls.assert_called_once_with(
        mock_token_manager_cls.return_value
    )
    mock_uvicorn_run.assert_called_once()
    self.assertIsInstance(
        mock_uvicorn_run.call_args[0][0], asgi.PromptEncryptionASGIMiddleware
    )
    self.assertEqual(
        mock_uvicorn_run.call_args[1],
        {
            "host": "localhost",
            "port": 8000,
            "http": asgi.TlsInjectorProtocol,
            "log_level": "info",
        },
    )
    mock_token_manager_cls.return_value.__exit__.assert_called_once()

  @mock.patch.object(asgi.uvicorn, "run", autospec=True)
  @mock.patch.object(attestation, "AttestedTLS", autospec=True)
  def test_run_uvicorn_app_with_managers(
      self,
      mock_attested_tls_cls,
      mock_uvicorn_run,
  ):
    mock_app = mock.MagicMock()
    mock_key_manager = mock.MagicMock()
    mock_token_manager = mock.MagicMock()
    asgi.run_uvicorn_app(
        mock_app,
        key_manager=mock_key_manager,
        token_manager=mock_token_manager,
        host="localhost",
        port=8000,
    )

    mock_token_manager.__enter__.assert_called_once()
    mock_attested_tls_cls.assert_called_once_with(mock_token_manager)
    mock_uvicorn_run.assert_called_once()
    self.assertIsInstance(
        mock_uvicorn_run.call_args[0][0], asgi.PromptEncryptionASGIMiddleware
    )
    self.assertEqual(
        mock_uvicorn_run.call_args[1],
        {
            "host": "localhost",
            "port": 8000,
            "http": asgi.TlsInjectorProtocol,
            "log_level": "info",
        },
    )
    mock_token_manager.__exit__.assert_called_once()

  @mock.patch.object(asgi.uvicorn, "run", autospec=True)
  @mock.patch.object(keys, "KeyManager", autospec=True)
  @mock.patch.object(token, "TokenManager", autospec=True)
  @mock.patch.object(attestation, "AttestedTLS", autospec=True)
  def test_run_uvicorn_app_with_log_config(
      self,
      mock_attested_tls_cls,
      mock_token_manager_cls,
      mock_key_manager_cls,
      mock_uvicorn_run,
  ):
    mock_app = mock.MagicMock()
    asgi.run_uvicorn_app(mock_app, host="localhost", port=8000, log_config={})

    mock_key_manager_cls.assert_called_once()
    mock_token_manager_cls.assert_called_once_with(
        key_manager=mock_key_manager_cls.return_value
    )
    mock_token_manager_cls.return_value.__enter__.assert_called_once()
    mock_attested_tls_cls.assert_called_once_with(
        mock_token_manager_cls.return_value
    )
    mock_uvicorn_run.assert_called_once()
    self.assertIsInstance(
        mock_uvicorn_run.call_args[0][0], asgi.PromptEncryptionASGIMiddleware
    )
    self.assertEqual(
        mock_uvicorn_run.call_args[1],
        {
            "host": "localhost",
            "port": 8000,
            "http": asgi.TlsInjectorProtocol,
            "log_config": {},
        },
    )
    mock_token_manager_cls.return_value.__exit__.assert_called_once()


class TlsInjectorProtocolTest(absltest.TestCase):

  def test_tls_injector_protocol_injects_ssl_object(self):
    async def run():
      original_app = mock.AsyncMock()
      config = uvicorn.Config(original_app)
      config.ws_protocol_class = None
      config.loaded = True
      config.loaded_app = original_app
      server_state = mock.MagicMock()
      app_state = {}

      protocol = asgi.TlsInjectorProtocol(
          config, server_state, app_state, _loop=asyncio.get_event_loop()
      )
      protocol.transport = mock.MagicMock()
      ssl_object = mock.MagicMock()
      protocol.transport.get_extra_info.return_value = ssl_object

      scope = {"type": "http"}
      receive = mock.AsyncMock()
      send = mock.AsyncMock()

      await protocol.app(scope, receive, send)

      self.assertEqual(scope["extensions"]["tls_socket"], ssl_object)
      original_app.assert_called_once_with(scope, receive, send)
      protocol.transport.get_extra_info.assert_called_once_with("ssl_object")

    asyncio.run(run())

  def test_tls_injector_protocol_no_transport(self):
    async def run():
      original_app = mock.AsyncMock()
      config = uvicorn.Config(original_app)
      config.ws_protocol_class = None
      config.loaded = True
      config.loaded_app = original_app
      server_state = mock.MagicMock()
      app_state = {}

      protocol = asgi.TlsInjectorProtocol(
          config, server_state, app_state, _loop=asyncio.get_event_loop()
      )
      protocol.transport = None

      scope = {"type": "http"}
      receive = mock.AsyncMock()
      send = mock.AsyncMock()

      await protocol.app(scope, receive, send)

      self.assertNotIn("extensions", scope)
      original_app.assert_called_once_with(scope, receive, send)

    asyncio.run(run())

  def test_tls_injector_protocol_no_ssl_object(self):
    async def run():
      original_app = mock.AsyncMock()
      config = uvicorn.Config(original_app)
      config.ws_protocol_class = None
      config.loaded = True
      config.loaded_app = original_app
      server_state = mock.MagicMock()
      app_state = {}

      protocol = asgi.TlsInjectorProtocol(
          config, server_state, app_state, _loop=asyncio.get_event_loop()
      )
      protocol.transport = mock.MagicMock()
      protocol.transport.get_extra_info.return_value = None

      scope = {"type": "http"}
      receive = mock.AsyncMock()
      send = mock.AsyncMock()

      await protocol.app(scope, receive, send)

      self.assertNotIn("extensions", scope)
      original_app.assert_called_once_with(scope, receive, send)
      protocol.transport.get_extra_info.assert_called_once_with("ssl_object")

    asyncio.run(run())

  def test_tls_injector_protocol_not_http(self):
    async def run():
      original_app = mock.AsyncMock()
      config = uvicorn.Config(original_app)
      config.ws_protocol_class = None
      config.loaded = True
      config.loaded_app = original_app
      server_state = mock.MagicMock()
      app_state = {}

      protocol = asgi.TlsInjectorProtocol(
          config, server_state, app_state, _loop=asyncio.get_event_loop()
      )
      protocol.transport = mock.MagicMock()
      protocol.transport.get_extra_info.return_value = mock.MagicMock()

      scope = {"type": "not-http"}
      receive = mock.AsyncMock()
      send = mock.AsyncMock()

      await protocol.app(scope, receive, send)

      self.assertNotIn("extensions", scope)
      original_app.assert_called_once_with(scope, receive, send)
      protocol.transport.get_extra_info.assert_not_called()

    asyncio.run(run())

  def test_tls_injector_protocol_injects_ssl_object_with_existing_extensions(
      self,
  ):
    async def run():
      original_app = mock.AsyncMock()
      config = uvicorn.Config(original_app)
      config.ws_protocol_class = None
      config.loaded = True
      config.loaded_app = original_app
      server_state = mock.MagicMock()
      app_state = {}

      protocol = asgi.TlsInjectorProtocol(
          config, server_state, app_state, _loop=asyncio.get_event_loop()
      )
      protocol.transport = mock.MagicMock()
      ssl_object = mock.MagicMock()
      protocol.transport.get_extra_info.return_value = ssl_object

      scope = {"type": "http", "extensions": {"other": 1}}
      receive = mock.AsyncMock()
      send = mock.AsyncMock()

      await protocol.app(scope, receive, send)

      self.assertEqual(scope["extensions"]["tls_socket"], ssl_object)
      self.assertEqual(scope["extensions"]["other"], 1)
      original_app.assert_called_once_with(scope, receive, send)
      protocol.transport.get_extra_info.assert_called_once_with("ssl_object")

    asyncio.run(run())


if __name__ == "__main__":
  absltest.main()
