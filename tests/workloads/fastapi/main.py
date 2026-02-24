"""FastAPI application for Prompt Encryption."""

import atexit
import datetime
import os
import tempfile

from prompt_encryption_sdk.server import asgi as middleware
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
import fastapi

app = fastapi.FastAPI()


@app.get("/hello")
async def handle_hello() -> dict[str, str]:
  return {"message": "Hello from a FastAPI App"}


def generate_self_signed_cert() -> tuple[
    rsa.RSAPrivateKey, x509.Certificate
]:
  """Generates a self-signed certificate and key.

  Returns:
    A tuple containing:
      key: The generated RSA private key.
      cert: The generated self-signed x509 certificate.
  """
  key = rsa.generate_private_key(
      public_exponent=65537,
      key_size=2048,
  )
  subject = issuer = x509.Name([
      x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
      x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
      x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
      x509.NameAttribute(NameOID.ORGANIZATION_NAME, "My Company"),
      x509.NameAttribute(NameOID.COMMON_NAME, "mysite.com"),
  ])
  cert = (
      x509.CertificateBuilder()
      .subject_name(subject)
      .issuer_name(issuer)
      .public_key(key.public_key())
      .serial_number(x509.random_serial_number())
      .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
      .not_valid_after(
          datetime.datetime.now(datetime.timezone.utc)
          + datetime.timedelta(days=10)
      )
      .add_extension(
          x509.SubjectAlternativeName([x509.DNSName("localhost")]),
          critical=False,
      )
      .sign(key, hashes.SHA256())
  )
  return key, cert


if __name__ == "__main__":
  key, cert = generate_self_signed_cert()
  with tempfile.NamedTemporaryFile(
      delete=False
  ) as cert_file, tempfile.NamedTemporaryFile(delete=False) as key_file:
    cert_file.write(cert.public_bytes(serialization.Encoding.PEM))
    key_file.write(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    cert_path, key_path = cert_file.name, key_file.name

  atexit.register(os.remove, cert_path)
  atexit.register(os.remove, key_path)

  middleware.run_uvicorn_app(
      app,
      host="0.0.0.0",
      port=8443,
      ssl_certfile=cert_path,
      ssl_keyfile=key_path,
  )
