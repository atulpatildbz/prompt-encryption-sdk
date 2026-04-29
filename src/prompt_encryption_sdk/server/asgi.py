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

"""ASGI middleware for handling attested TLS connections."""

import json
import logging
from prompt_encryption_sdk.proto import attestation_pb2
from prompt_encryption_sdk.server import attestation
from prompt_encryption_sdk.server import keys
from prompt_encryption_sdk.server import token
from google.protobuf import json_format
from starlette import requests
from starlette import responses
from uvicorn.config import Config
import uvicorn
from uvicorn.protocols.http.h11_impl import H11Protocol

class TlsInjectorProtocol(H11Protocol):

  def __init__(
      self,
      config: Config,
      server_state,
      app_state,
      _loop=None,
      **kwargs,
  ):
    super().__init__(config, server_state, app_state, _loop, **kwargs)
    self.original_app = self.app

    async def app_wrapper(scope, receive, send):
      if scope["type"] == "http":
        transport = self.transport
        if transport:
          ssl_obj = transport.get_extra_info("ssl_object")
          if ssl_obj:
            if "extensions" not in scope:
              scope["extensions"] = {}
            scope["extensions"]["tls_socket"] = ssl_obj
      await self.original_app(scope, receive, send)

    self.app = app_wrapper


class PromptEncryptionASGIMiddleware:
  """ASGI middleware for handling attested TLS connections.

  Attributes:
    app: The ASGI application to wrap.
    attested_tls: An instance of `attestation.AttestedTLS` used for handling
      attestation.
  """

  def __init__(self, app, attested_tls: attestation.AttestedTLS):
    self.app = app
    self.attested_tls = attested_tls

  async def __call__(self, scope, receive, send):
    if scope["type"] == "http" and scope["path"] == "/_attest-connection":
      try:
        await self.handle_attestation(scope, receive, send)
      except Exception as e:  # pylint: disable=broad-except
        logging.exception("Error during handling attest connection request")
        status_code = 400 if isinstance(e, json_format.ParseError) else 500
        error_response = responses.JSONResponse(
            {"error": f"An internal server error occurred: {repr(e)}"},
            status_code=status_code,
        )
        await error_response(scope, receive, send)
      return

    await self.app(scope, receive, send)

  async def handle_attestation(self, scope, receive, send):
    """Handles the requests to /_attest-connection.

    Args:
      scope: The ASGI scope.
      receive: The ASGI receive function.
      send: The ASGI send function.
    """
    request = requests.Request(scope, receive)
    raw_body = await request.body()
    req = json_format.Parse(
        raw_body,
        attestation_pb2.AttestConnectionRequest(),
        ignore_unknown_fields=True,
    )

    extensions = scope.get("extensions", {})
    ssl_obj = extensions.get("tls_socket")

    if not ssl_obj:
      raise RuntimeError("TLS Socket not found.")

    attestation_response_proto = self.attested_tls.attest_connection(
        req, ssl_obj=ssl_obj
    )
    attestation_response_dict = json_format.MessageToDict(
        attestation_response_proto
    )
    response = responses.JSONResponse(attestation_response_dict)
    await response(scope, receive, send)


def run_uvicorn_app(
    app, *, key_manager=None, token_manager=None, **kwargs
) -> None:
  """Runs a uvicorn app with PromptEncryptionASGIMiddleware.

  Args:
    app: The ASGI application to run.
    key_manager: An optional keys.KeyManager instance. If not provided, a new
      one will be created.
    token_manager: An optional token.TokenManager instance. If not provided, a
      new one will be created using the key_manager.
    **kwargs: Additional keyword arguments to pass to uvicorn.run.
  """
  if key_manager is None:
    key_manager = keys.KeyManager()
  if token_manager is None:
    token_manager = token.TokenManager(key_manager=key_manager)
  kwargs["http"] = TlsInjectorProtocol
  if "log_config" not in kwargs:
    kwargs["log_level"] = kwargs.get("log_level", "info")
  with token_manager:
    atls = attestation.AttestedTLS(token_manager)
    protected_app = PromptEncryptionASGIMiddleware(app, atls)
    uvicorn.run(protected_app, **kwargs)
