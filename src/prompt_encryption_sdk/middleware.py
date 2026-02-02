"""Starlette/ASGI middleware for handling attested TLS connections.

This middleware intercepts requests to `/_attest-connection` and returns
the response for attested TLS.
"""

import logging
from attested_confidential_inference import attested_tls as at
from attested_confidential_inference.proto import attestation_pb2
from google.protobuf import json_format
from starlette import exceptions
from starlette import requests
from starlette import responses
import uvicorn


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
      await self.handle_attestation(scope, receive, send)
      return

    await self.app(scope, receive, send)

  async def handle_attestation(self, scope, receive, send):
    """Handles the requests to /_attest-connection.

    Args:
      scope: The ASGI scope.
      receive: The ASGI receive function.
      send: The ASGI send function.
    """
    try:
      request = requests.Request(scope, receive)
      body = await request.body()
      req = json_format.Parse(body, attestation_pb2.AttestConnectionRequest())
      attestation_response_proto = self.attested_tls.attest_connection(req)
      attestation_response_dict = json_format.MessageToDict(
          attestation_response_proto
      )
      response = responses.JSONResponse(attestation_response_dict)
      await response(scope, receive, send)
    except json_format.ParseError:
      logging.exception("Error parsing AttestConnectionRequest")
      error_response = responses.JSONResponse(
          {"error": "Invalid request"}, status_code=400
      )
      await error_response(scope, receive, send)
    except Exception as e:  # pylint: disable=broad-except
      logging.exception("Error during handling attest connection request")
      error_response = responses.JSONResponse(
          {"error": f"An internal server error occurred: {repr(e)}"},
          status_code=500,
      )
      await error_response(scope, receive, send)


def run_uvicorn_app(app, key_manager=None, token_manager=None, **kwargs):
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
  with token_manager:
    atls = at.AttestedTLS(token_manager)
    protected_app = ConfidentialASGIMiddleware(app, atls)
    uvicorn.run(protected_app, **kwargs)
