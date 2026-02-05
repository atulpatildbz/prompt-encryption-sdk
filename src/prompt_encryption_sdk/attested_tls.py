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

"""Function for handling AttestConnection logic."""

from collections.abc import Callable
import hashlib
import http.client
import json
import os
import pathlib
import random
import socket
import types
import threading
import time
from typing import Any, Protocol

from absl import logging
from attested_confidential_inference.proto import attestation_pb2
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
import jwt

TEE_SERVER_SOCKET_PATH = "/run/container_launcher/teeserver.sock"
TOKEN_ENDPOINT = "/v1/token"
DEFAULT_AUDIENCE = "https://sts.google.com"
TOKEN_TYPE = "OIDC"
DEFAULT_REFRESH_MULTIPLIER = 0.9
DEFAULT_RETRY_INTERVAL_SECONDS = 10


class _FileWriter(Protocol):

  def __call__(self, path: pathlib.Path, data: bytes, mode: int) -> None:
    ...


class _FileReader(Protocol):

  def __call__(self, path: pathlib.Path) -> bytes:
    ...


class UnixSocketConnection(http.client.HTTPConnection):
  """HTTPConnection that connects to a Unix domain socket."""

  def __init__(self, socket_path: pathlib.Path):
    super().__init__("localhost")
    self.socket_path = str(socket_path)

  def connect(self):
    self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    self.sock.connect(self.socket_path)

  def __enter__(self) -> "UnixSocketConnection":
    return self

  def __exit__(
      self,
      exc_type: type[BaseException] | None,
      exc_val: BaseException | None,
      exc_tb: types.TracebackType | None,
  ) -> None:
    self.close()

  def __repr__(self):
    return f"UnixSocketConnection(socket_path={self.socket_path!r})"


class KeyManager:
  """Manages the generation, storage, and rotation of cryptographic keys."""

  def __init__(
      self,
      *,
      private_key_path: pathlib.Path = pathlib.Path("private_key.pem"),
      public_key_path: pathlib.Path = pathlib.Path("public_key.pem"),
      write_file_fn: _FileWriter | None = None,
      read_file_fn: _FileReader | None = None,
  ):
    """Initializes the KeyManager.

    Args:
        private_key_path: File path to store the private key.
        public_key_path: File path to store the public key.
        write_file_fn: Function to write files. Defaults to the internal
          `_write_file`.
        read_file_fn: Function to read files. Defaults to the internal
          `_read_file`.
    """
    self.private_key_path = private_key_path
    self.public_key_path = public_key_path
    self._write_file_fn = (
        write_file_fn if write_file_fn is not None else _write_file
    )
    self._read_file_fn = (
        read_file_fn if read_file_fn is not None else _read_file
    )

  def __repr__(self):
    return (
        f"KeyManager(private_key_path={self.private_key_path!r},"
        f" public_key_path={self.public_key_path!r},"
        f" write_file_fn={self._write_file_fn!r},"
        f" read_file_fn={self._read_file_fn!r})"
    )

  def generate_key_pair(self) -> bytes:
    """Generates a new ECDSA P-256 key pair and returns the public key."""
    logging.info(
        "Generating new key pair. Private key path: %s, Public key path: %s",
        self.private_key_path,
        self.public_key_path,
    )

    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()

    pem_private = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    pem_public = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    self._write_file_fn(self.private_key_path, pem_private, 0o600)
    self._write_file_fn(self.public_key_path, pem_public, 0o644)

    logging.info(
        "Successfully generated new key pair. Private key saved to: %s, Public"
        " key saved to: %s",
        self.private_key_path,
        self.public_key_path,
    )
    return pem_public

  def get_current_public_key(self) -> bytes:
    """Reads and returns the public key bytes."""
    return self._read_file_fn(self.public_key_path)


class TokenManager:
  """A manager for refreshing of keys and attestation tokens."""

  def __init__(
      self,
      *,
      key_manager: KeyManager,
      jitter_window_seconds: float = 60.0,
      rng: random.Random | None = None,
      attestation_token_path: pathlib.Path = pathlib.Path(
          "attestation_token.txt"
      ),
  ):
    self.key_manager = key_manager
    self.attestation_token_path = attestation_token_path
    self.jitter_window_seconds = jitter_window_seconds
    self.rng = rng if rng is not None else random.Random()
    self._stop_event = threading.Event()
    self._thread = threading.Thread(target=self._run, daemon=True)
    self._lock = threading.Lock()

  def __repr__(self):
    return (
        f"TokenManager(key_manager={self.key_manager!r},"
        f" attestation_token_path={self.attestation_token_path!r},"
        f" jitter_window_seconds={self.jitter_window_seconds!r}"
    )

  def refresh(self) -> None:
    """Refreshes the public key and attestation token and saves them to files."""
    logging.info("Refreshing keys and attestation token...")
    with self._lock:
      self.key_manager.generate_key_pair()
      public_key = self.key_manager.get_current_public_key()
      public_key_fingerprint = calculate_fingerprint(public_key)

      attestation_token = get_custom_token_bytes(
          audience=DEFAULT_AUDIENCE,
          token_type=TOKEN_TYPE,
          nonces=[public_key_fingerprint],
      )
      _write_file(self.attestation_token_path, attestation_token, 0o644)
    logging.info("Refresh complete.")

  def get_public_key(self) -> bytes:
    """Gets the current public key from the key manager."""
    with self._lock:
      return self.key_manager.get_current_public_key()

  def get_attestation_token(self) -> bytes:
    """Gets the current attestation token from its file."""
    with self._lock:
      try:
        with open(self.attestation_token_path, "rb") as f:
          return f.read()
      except FileNotFoundError:
        return b""

  def get_identity_snapshot(self) -> tuple[bytes, bytes]:
    """Gets the current public key and attestation token together."""
    with self._lock:
      public_key = self.key_manager.get_current_public_key()
      try:
        with open(self.attestation_token_path, "rb") as f:
          token = f.read()
      except FileNotFoundError:
        token = b""
      return public_key, token

  def _calculate_refresh_duration(self) -> float:
    """Calculates how long to sleep until the 90% mark, minus jitter."""
    token_bytes = self.get_attestation_token()

    if not token_bytes:
      logging.info("No token found. Refresh needed immediately.")
      return 0.0

    try:
      claims = jwt.decode(
          token_bytes.decode("utf-8"), options={"verify_signature": False}
      )
      exp = claims.get("exp")
      iat = claims.get("iat")
    except (
        jwt.exceptions.DecodeError,
        jwt.exceptions.InvalidTokenError,
        jwt.exceptions.InvalidSignatureError,
        jwt.exceptions.InvalidAlgorithmError,
    ):
      logging.exception(
          "Failed to parse token from %r for timing. Refreshing immediately.",
          self.attestation_token_path,
      )
      return 0.0

    if not exp or not iat:
      return 0.0

    now = time.time()
    lifespan = exp - iat
    target_time = iat + (lifespan * DEFAULT_REFRESH_MULTIPLIER)

    wait_seconds = target_time - now
    jitter = self.rng.uniform(0, self.jitter_window_seconds)
    return max(0.0, wait_seconds - jitter)

  def _run(self):
    """Checks if the token is expired based on iat and exp claims."""
    while not self._stop_event.is_set():
      try:
        sleep_duration = self._calculate_refresh_duration()
        if self._stop_event.wait(timeout=sleep_duration):
          break
        self.refresh()

      except (OSError, RuntimeError, ValueError):
        logging.exception("Refresher failed with unexpected error.")
        time.sleep(DEFAULT_RETRY_INTERVAL_SECONDS)

  def __enter__(self) -> "TokenManager":
    logging.info("Starting token manager.")
    self._thread.start()
    self._stop_event.clear()
    return self

  def __exit__(
      self,
      exc_type: type[BaseException] | None,
      exc_val: BaseException | None,
      exc_tb: types.TracebackType | None,
  ) -> None:
    logging.info("Stopping token manager.")
    self._stop_event.set()
    self._thread.join()


class AttestedTLS:
  """Handles AttestConnection logic."""

  def __init__(self, token_manager: TokenManager):
    self.token_manager = token_manager

  def __repr__(self):
    return f"AttestedTLS(token_manager={self.token_manager!r})"

  def attest_connection(
      self,
      request: attestation_pb2.AttestConnectionRequest,
  ) -> attestation_pb2.AttestConnectionResponse:
    """Processes the AttestConnectionRequest and returns an AttestConnectionResponse.

    This function returns an attested TLS response containing an attestation
    token with the hash of the server's public key embedded in it. It also signs
    the TLS session material and hash of the attestation token with the private
    key and includes the signature in the response.

    Args:
      request: The AttestConnectionRequest message.

    Returns:
      An AttestConnectionResponse message containing the attestation token and
      the server's public key and signed TLS session material.

    Raises:
      ValueError: If no required_verifier_type is specified or if an unsupported
        verifier type is requested.
    """
    if not request.required_verifier_type:
      raise ValueError("At least one required_verifier_type must be specified.")

    if (
        attestation_pb2.VerifierType.VERIFIER_TYPE_GCA
        not in request.required_verifier_type
    ):
      raise ValueError(
          "Unsupported verifier types requested:"
          f" {request.required_verifier_type}"
      )

    public_key, attestation_token = self.token_manager.get_identity_snapshot()
    response = attestation_pb2.AttestConnectionResponse(
        evidence=[
            attestation_pb2.AttestationEvidence(
                verifier_type=attestation_pb2.VerifierType.VERIFIER_TYPE_GCA,
                gca_bundle=attestation_pb2.GcaTrustBundle(
                    attestation_token=attestation_token.decode("utf-8")
                ),
            )
        ],
        instance_public_key=attestation_pb2.EcdsaP256PublicKey(
            key_bytes=public_key
        ),
    )
    # TODO: b/463825032 - Update it to include signed EKM.
    return response


def get_custom_token_bytes(
    socket_path: pathlib.Path = pathlib.Path(TEE_SERVER_SOCKET_PATH),
    connection_factory: Callable[
        [pathlib.Path], http.client.HTTPConnection
    ] = UnixSocketConnection,
    **kwargs: Any,
) -> bytes:
  """Retrieves custom attestation token bytes via TEE server."""
  conn = connection_factory(socket_path)
  with conn:
    headers = {"Content-Type": "application/json"}
    body = json.dumps(kwargs).encode("utf-8")
    conn.request("POST", TOKEN_ENDPOINT, body=body, headers=headers)

    response = conn.getresponse()
    if response.status >= 400:
      raise RuntimeError(
          f"HTTP Error {response.status}: {response.reason} for request body:"
          f" {body}"
      )

    logging.info(
        "Successfully retrieved attestation token from socket: %s", socket_path
    )
    return response.read()


def calculate_fingerprint(public_key: bytes) -> str:
  """Calculates the SHA-256 fingerprint of the public key."""
  return hashlib.sha256(public_key).hexdigest()


def _write_file(path: pathlib.Path, data: bytes, mode: int) -> None:
  """Helper to write files atomically."""
  path = pathlib.Path(path)
  temp_path = path.with_name(path.name + ".tmp")
  try:
    fd = os.open(temp_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(fd, "wb") as f:
      f.write(data)
    os.replace(temp_path, path)
  except Exception as e:
    if temp_path.exists():
      os.remove(temp_path)
    raise ValueError(f"Could not write file atomically: {path!r}") from e


def _read_file(path: pathlib.Path) -> bytes:
  """Helper to read files safely."""
  try:
    with open(path, "rb") as f:
      return f.read()
  except OSError as err:
    raise ValueError(f"Could not read file: {path!r}") from err
