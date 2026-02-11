"""Starlette/ASGI middleware for handling attested TLS connections.

This middleware intercepts requests to `/_attest-connection` and returns
the response for attested TLS.
"""

import logging
import json
from attested_confidential_inference import attested_tls as at
from attested_confidential_inference.proto import attestation_pb2
from google.protobuf import json_format
from starlette import requests
from starlette import responses
import uvicorn
from uvicorn.config import Config
from uvicorn.protocols.http.h11_impl import H11Protocol


class TlsInjectorProtocol(H11Protocol):

  def __init__(
      self, config: Config, server_state, app_state, _loop=None, **kwargs
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


class ConfidentialASGIMiddleware:
  """ASGI middleware for handling attested TLS connections.

  Attributes:
    app: The ASGI application to wrap.
    attested_tls: An instance of `attested_tls.AttestedTLS` used for handling
      attestation.
  """

  def __init__(self, app, attested_tls):
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
    try:
      decoded_body = raw_body.decode("utf-8")
      data = json.loads(decoded_body)
    except (json.JSONDecodeError, UnicodeDecodeError):
      data = {}

    req = json_format.Parse(
        raw_body,
        attestation_pb2.AttestConnectionRequest(),
        ignore_unknown_fields=True,
    )

    label = data.get("label", "EXPORTER-Confidential-Inference")
    extensions = scope.get("extensions", {})
    ssl_obj = extensions.get("tls_socket")

    if not ssl_obj:
      raise RuntimeError("TLS Socket not found.")

    attestation_response_proto = self.attested_tls.attest_connection(
        req, ssl_obj, label
    )
    attestation_response_dict = json_format.MessageToDict(
        attestation_response_proto
    )
    response = responses.JSONResponse(attestation_response_dict)
    await response(scope, receive, send)


def run_uvicorn_app(app, key_manager=None, token_manager=None, **kwargs) -> None:
  """Runs a uvicorn app with ConfidentialASGIMiddleware.

  Args:
    app: The ASGI application to run.
    key_manager: An optional at.KeyManager instance. If not provided, a new one
      will be created.
    token_manager: An optional at.TokenManager instance. If not provided, a new
      one will be created using the key_manager.
    **kwargs: Additional keyword arguments to pass to uvicorn.run.
  """
  if key_manager is None:
    key_manager = at.KeyManager()
  if token_manager is None:
    token_manager = at.TokenManager(key_manager=key_manager)
  kwargs["http"] = TlsInjectorProtocol
  if "log_config" not in kwargs:
    kwargs["log_level"] = kwargs.get("log_level", "info")
  with token_manager:
    atls = at.AttestedTLS(token_manager)
    protected_app = ConfidentialASGIMiddleware(app, atls)
    uvicorn.run(protected_app, **kwargs)
