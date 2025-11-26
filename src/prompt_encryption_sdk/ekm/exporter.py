"""EKM Exporter Module.

Provides functionality to extract TLS Exported Keying Material (RFC 5705)
from Python ssl.SSLSockets.
"""

import ssl
from typing import Optional
from . import _ekm


def export_keying_material(
    sock: ssl.SSLSocket,
    length: int,
    label: bytes,
    context: Optional[bytes] = None,
) -> bytes:
  """Exports keying material from an established TLS connection.

  This function uses a C extension to access the underlying OpenSSL `SSL_export_keying_material`
  function.

  Args:
      sock: An active, handshaked ssl.SSLSocket.
      length: The number of bytes of keying material to generate.
      label: The ASCII label for the keying material (e.g., b"EXPORTER-My-Label").
      context: Optional binary context for binding the keying material to specific
        application data.

  Returns:
      The extracted keying material of the requested length.

  Raises:
      TypeError: If the socket is not a valid SSLSocket.
      ValueError: If the socket is not connected or handshaked.
      RuntimeError: If the OpenSSL export function fails.
  """
  if sock is None:
    raise TypeError('Socket cannot be None')

  # The C extension needs access to the underlying socket object, but Python's
  # ssl module sometimes wraps it. Access the private _sslobj attribute
  # recursively to retrieve the innermost socket object.
  internal_sock = sock
  while hasattr(internal_sock, '_sslobj'):
    internal_sock = internal_sock._sslobj

  # Before passing to C, check if the object looks like an SSL socket.
  # This is a heuristic check to prevent passing arbitrary types to C code.
  if type(internal_sock).__module__ != '_ssl':
    raise TypeError(
        f'Provided object of type {type(internal_sock).__name__} does not '
        'appear to be a valid SSL socket object.'
    )

  return _ekm.export_keying_material(internal_sock, length, label, context)
