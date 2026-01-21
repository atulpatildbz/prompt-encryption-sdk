"""Function for handling AttestConnection logic."""

from collections.abc import Callable
import hashlib
import http.client
import json
import os
import pathlib
import socket
from types import TracebackType
from typing import Any, Protocol
from absl import logging
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

TEE_SERVER_SOCKET_PATH = "/run/container_launcher/teeserver.sock"
TOKEN_ENDPOINT = "/v1/token"
DEFAULT_AUDIENCE = "https://sts.google.com"
TOKEN_TYPE = "OIDC"


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
      exc_tb: TracebackType | None,
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
  """Helper to write files safely."""
  fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
  with os.fdopen(fd, "wb") as f:
    f.write(data)


def _read_file(path: pathlib.Path) -> bytes:
  """Helper to read files safely."""
  try:
    with open(path, "rb") as f:
      return f.read()
  except OSError as err:
    raise ValueError(f"Could not read file: {path!r}") from err
