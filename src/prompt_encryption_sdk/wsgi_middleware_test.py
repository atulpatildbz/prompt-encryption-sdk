import json
from unittest import mock

from absl.testing import absltest
from attested_confidential_inference import attested_tls as at
from attested_confidential_inference import wsgi_middleware
from attested_confidential_inference.proto import attestation_pb2
from google.protobuf import json_format
import werkzeug.test

from google3.net.proto2.contrib.pyutil import compare


class ConfidentialWSGIMiddlewareTest(
    absltest.TestCase, compare.Proto2Assertions
):

  def setUp(self):
    super().setUp()
    self.mock_attested_tls = mock.create_autospec(at.AttestedTLS, instance=True)

    def simple_app(unused_environ, unused_start_response):
      pass

    self.app = mock.create_autospec(simple_app)
    self.mw = wsgi_middleware.ConfidentialWSGIMiddleware(
        self.app, self.mock_attested_tls
    )
    self.client = werkzeug.test.Client(self.mw)

  def test_call_other_path(self):
    def simple_app(_, start_response):
      start_response("200 OK", [("Content-Type", "text/plain")])
      return [b"ok"]

    self.app.side_effect = simple_app
    response = self.client.get("/other")
    self.assertEqual(response.status_code, 200)
    self.assertEqual(response.data, b"ok")
    self.app.assert_called_once()

  def test_handle_attestation_success(self):
    request_proto = attestation_pb2.AttestConnectionRequest()
    request_json = json_format.MessageToJson(request_proto)

    response_proto = attestation_pb2.AttestConnectionResponse(
        instance_public_key=attestation_pb2.EcdsaP256PublicKey(
            key_bytes=b"test_public_key"
        )
    )
    self.mock_attested_tls.attest_connection.return_value = response_proto

    # Mock the socket injection in environ
    environ_overrides = {"confidential_inference.socket": mock.Mock()}

    response = self.client.post(
        "/_attest-connection",
        json=json.loads(request_json),
        environ_overrides=environ_overrides,
    )

    self.mock_attested_tls.attest_connection.assert_called_once_with(
        request_proto,
        ssl_obj=environ_overrides["confidential_inference.socket"],
        label="EXPORTER-Confidential-Inference",
    )
    self.assertEqual(response.status_code, 200)

    response_proto_parsed = json_format.Parse(
        response.data, attestation_pb2.AttestConnectionResponse()
    )
    self.assertProto2Equal(response_proto_parsed, response_proto)

  def test_handle_attestation_missing_socket(self):
    request_proto = attestation_pb2.AttestConnectionRequest()
    request_json = json_format.MessageToJson(request_proto)

    response = self.client.post(
        "/_attest-connection", json=json.loads(request_json)
    )

    # Expect 500 because RuntimeError is raised
    self.assertEqual(response.status_code, 500)
    self.assertIn(b"TLS Socket not found", response.data)

  def test_handle_attestation_parse_error(self):

    # Mock json_format.Parse to simulate a protobuf parsing error, as it is difficult
    # to trigger a pure ParseError with standard JSON inputs due to permissive parsing.
    with mock.patch.object(
        wsgi_middleware.json_format,
        "Parse",
        side_effect=wsgi_middleware.json_format.ParseError("test"),
    ):
      response = self.client.post("/_attest-connection", json={})
      self.assertEqual(response.status_code, 400)
      self.assertIn(b"Invalid request", response.data)

  def test_handle_attestation_internal_error(self):
    request_proto = attestation_pb2.AttestConnectionRequest()
    request_json = json_format.MessageToJson(request_proto)

    environ_overrides = {"confidential_inference.socket": mock.Mock()}

    self.mock_attested_tls.attest_connection.side_effect = ValueError(
        "test error"
    )

    response = self.client.post(
        "/_attest-connection",
        json=json.loads(request_json),
        environ_overrides=environ_overrides,
    )

    self.assertEqual(response.status_code, 500)
    self.assertIn(b"test error", response.data)

  def test_run_gunicorn_app(self):
    mock_app = mock.Mock()
    mock_key_manager = mock.create_autospec(at.KeyManager, instance=True)
    mock_token_manager = mock.create_autospec(at.TokenManager, instance=True)
    mock_attested_tls_cls = mock.create_autospec(at.AttestedTLS, instance=False)
    mock_standalone_app_cls = mock.create_autospec(
        wsgi_middleware._StandaloneApplication, instance=False
    )
    mock_standalone_app_instance = mock_standalone_app_cls.return_value

    wsgi_middleware.run_gunicorn_app(
        mock_app,
        key_manager=mock_key_manager,
        token_manager=mock_token_manager,
        host="localhost",
        port=9000,
        attested_tls_cls=mock_attested_tls_cls,
        standalone_app_cls=mock_standalone_app_cls,
    )

    with self.subTest("AttestedTLS"):
      mock_attested_tls_cls.assert_called_once_with(mock_token_manager)

    with self.subTest("StandaloneApplication"):
      mock_standalone_app_cls.assert_called_once_with(
          mock.ANY,
          {
              "bind": "localhost:9000",
              "workers": 1,
              "worker_class": wsgi_middleware.ConfidentialGunicornWorker,
              "certfile": None,
              "keyfile": None,
              "accesslog": "-",
              "errorlog": "-",
          },
      )
      mock_standalone_app_instance.run.assert_called_once()

  def test_middleware_repr(self):
    self.assertEqual(
        repr(self.mw),
        f"<ConfidentialWSGIMiddleware app={self.app!r}>",
    )

  def test_patched_wsgi_create(self):
    mock_req = mock.Mock()
    mock_req.confidential_socket = "socket_obj"
    mock_environ = {}

    with mock.patch.object(
        wsgi_middleware, "_original_create", return_value=("resp", mock_environ)
    ) as mock_original:
      resp, environ = wsgi_middleware._patched_wsgi_create(mock_req)

    self.assertEqual(resp, "resp")
    self.assertEqual(environ["confidential_inference.socket"], "socket_obj")
    mock_original.assert_called_once_with(mock_req)

  def test_patched_wsgi_create_no_socket(self):
    # spec=[] ensures no extra attributes like confidential_socket exist
    mock_req = mock.Mock(spec=[])
    mock_environ = {}

    with mock.patch.object(
        wsgi_middleware, "_original_create", return_value=("resp", mock_environ)
    ) as mock_original:
      resp, environ = wsgi_middleware._patched_wsgi_create(mock_req)

    self.assertEqual(resp, "resp")
    self.assertNotIn("confidential_inference.socket", environ)
    mock_original.assert_called_once_with(mock_req)

  def _create_worker(self):
    # Mock arguments for Worker.__init__
    mock_age = mock.Mock()
    mock_ppid = mock.Mock()
    mock_sockets = mock.Mock()
    mock_app_inst = mock.Mock()
    mock_timeout = mock.Mock()
    mock_cfg = mock.Mock()
    mock_cfg.max_requests = 0
    mock_cfg.umask = 0
    mock_cfg.worker_tmp_dir = None
    mock_cfg.uid = 0
    mock_cfg.gid = 0
    mock_log = mock.Mock()

    # Create the worker instance
    with mock.patch("os.chown"):
      worker = wsgi_middleware.ConfidentialGunicornWorker(
          mock_age,
          mock_ppid,
          mock_sockets,
          mock_app_inst,
          mock_timeout,
          mock_cfg,
          mock_log,
      )
    return worker

  def test_worker_repr(self):
    worker = self._create_worker()
    # Manually set pid since it's set in __init__ but we want to be sure
    worker.pid = 12345

    self.assertEqual(repr(worker), "<ConfidentialGunicornWorker pid=12345>")

  def test_worker_handle_request(self):
    worker = self._create_worker()
    mock_req = mock.Mock()
    mock_client = mock.Mock()

    with mock.patch(
        "gunicorn.workers.sync.SyncWorker.handle_request"
    ) as mock_super_handle:
      worker.handle_request("listener", mock_req, mock_client, "addr")

    self.assertEqual(mock_req.confidential_socket, mock_client)
    mock_super_handle.assert_called_once_with(
        "listener", mock_req, mock_client, "addr"
    )

  def test_worker_handle_request_no_client(self):
    worker = self._create_worker()
    mock_req = mock.Mock(spec=[])
    mock_client = None

    with mock.patch(
        "gunicorn.workers.sync.SyncWorker.handle_request"
    ) as mock_super_handle:
      worker.handle_request("listener", mock_req, mock_client, "addr")

    self.assertFalse(hasattr(mock_req, "confidential_socket"))
    mock_super_handle.assert_called_once_with(
        "listener", mock_req, mock_client, "addr"
    )

  def test_parse_request_error_handling(self):
    # Force _parse_request to hit the except block
    with mock.patch.object(
        wsgi_middleware.werkzeug.wrappers,
        "Request",
        side_effect=Exception("Boom"),
    ):
      environ_overrides = {"confidential_inference.socket": mock.Mock()}
      self.mock_attested_tls.attest_connection.return_value = (
          attestation_pb2.AttestConnectionResponse()
      )

      response = self.client.post(
          "/_attest-connection", environ_overrides=environ_overrides
      )

      self.assertEqual(response.status_code, 200)
      # Verify attest_connection called with empty request (result of fallback)
      args, _ = self.mock_attested_tls.attest_connection.call_args
      self.assertEqual(args[0], attestation_pb2.AttestConnectionRequest())


class StandaloneApplicationTest(absltest.TestCase):

  def test_load_and_config(self):
    app = mock.Mock()
    options = {"bind": "1.2.3.4:5678"}

    # Mock BaseApplication.__init__ to verify load_config separately and avoid side effects
    with mock.patch(
        "gunicorn.app.base.BaseApplication.__init__", return_value=None
    ):
      sa = wsgi_middleware._StandaloneApplication(app, options)
      # Manually set attributes normally set by __init__
      sa.application = app
      sa.options = options
      sa.cfg = mock.Mock()
      sa.cfg.settings = {"bind": None}

      # Test load_config
      sa.load_config()
      sa.cfg.set.assert_called_with("bind", "1.2.3.4:5678")

      # Test load
      self.assertEqual(sa.load(), app)


if __name__ == "__main__":
  absltest.main()
