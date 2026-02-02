"""Tests for middleware."""

import asyncio
from unittest import mock

from absl.testing import absltest
from attested_confidential_inference import attested_tls as at
from attested_confidential_inference import middleware
from attested_confidential_inference.proto import attestation_pb2
from google.protobuf import json_format


class MiddlewareTest(absltest.TestCase):

  def setUp(self):
    super().setUp()
    self.mock_attested_tls = mock.create_autospec(at.AttestedTLS, instance=True)
    self.app = mock.AsyncMock()
    self.mw = middleware.ConfidentialASGIMiddleware(
        self.app, self.mock_attested_tls
    )
    self.send = mock.AsyncMock()

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
      }
      request_proto = attestation_pb2.AttestConnectionRequest()
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

      self.mock_attested_tls.attest_connection.assert_called_once()
      calls = self.send.call_args_list
      self.assertEqual(calls[0].args[0]["type"], "http.response.start")
      self.assertEqual(calls[0].args[0]["status"], 200)
      self.assertEqual(calls[1].args[0]["type"], "http.response.body")
      self.assertEqual(
          calls[1].args[0]["body"],
          json_format.MessageToJson(response_proto).encode("utf-8"),
      )

    asyncio.run(run())

  def test_attest_connection_parse_error(self):
    async def run():
      scope = {
          "type": "http",
          "path": "/_attest-connection",
          "method": "POST",
          "headers": [],
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
      self.assertEqual(calls[1].args[0]["body"], b'{"error":"Invalid request"}')

    asyncio.run(run())

  def test_attest_connection_internal_error(self):
    async def run():
      scope = {
          "type": "http",
          "path": "/_attest-connection",
          "method": "POST",
          "headers": [],
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
      self.assertEqual(
          calls[1].args[0]["body"],
          b'{"error":"An internal server error occurred: ValueError(\'test'
          b" error')\"}",
      )

    asyncio.run(run())

  @mock.patch.object(middleware.uvicorn, "run", autospec=True)
  @mock.patch.object(at, "KeyManager", autospec=True)
  @mock.patch.object(at, "TokenManager", autospec=True)
  @mock.patch.object(at, "AttestedTLS", autospec=True)
  def test_run_uvicorn_app_defaults(
      self,
      mock_attested_tls_cls,
      mock_token_manager_cls,
      mock_key_manager_cls,
      mock_uvicorn_run,
  ):
    mock_app = mock.MagicMock()
    middleware.run_uvicorn_app(mock_app, host="localhost", port=8000)

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
        mock_uvicorn_run.call_args[0][0], middleware.ConfidentialASGIMiddleware
    )
    self.assertEqual(
        mock_uvicorn_run.call_args[1], {"host": "localhost", "port": 8000}
    )
    mock_token_manager_cls.return_value.__exit__.assert_called_once()

  @mock.patch.object(middleware.uvicorn, "run", autospec=True)
  @mock.patch.object(at, "AttestedTLS", autospec=True)
  def test_run_uvicorn_app_with_managers(
      self,
      mock_attested_tls_cls,
      mock_uvicorn_run,
  ):
    mock_app = mock.MagicMock()
    mock_key_manager = mock.MagicMock()
    mock_token_manager = mock.MagicMock()
    middleware.run_uvicorn_app(
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
        mock_uvicorn_run.call_args[0][0], middleware.ConfidentialASGIMiddleware
    )
    self.assertEqual(
        mock_uvicorn_run.call_args[1], {"host": "localhost", "port": 8000}
    )
    mock_token_manager.__exit__.assert_called_once()
