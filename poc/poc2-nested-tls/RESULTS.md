# POC 2 — Nested-TLS loopback — RESULTS

**Date:** 2026-06-05 · **Env:** MacBook M4, podman 5.7.1, Envoy `v1.34-latest` (official arm64 image)
**Status:** ✅ PASS

## Goal
Prove (a) Envoy's `internal_listener` loopback works, and (b) nested TLS (TLS-in-TLS)
terminates such that the **inner** TLS ends *inside Envoy* and a WASM filter on the internal
listener sees the **decrypted** HTTP. Gates OPEN #4 (where inner TLS terminates).

## Topology built
```
curl (inner TLS + h2)
  -> :11000  socat TCP-LISTEN
  -> OUTER TLS  (socat OPENSSL-CONNECT)
  -> :10000  Envoy public listener  [terminates OUTER TLS]  (cert CN=outer-tls)
  -> tcp_proxy -> cluster inner_cluster -> envoy_internal_address(server_listener_name: inner)
  -> internal listener  [terminates INNER TLS]  (cert CN=inner-tls)
  -> HCM -> WASM probe (logs cleartext) -> direct_response "inner-ok"
```
Config: `envoy.yaml`. Probe filter: `probe/src/lib.rs` (HTTP filter, logs request + TLS props).
Certs: self-signed `certs/outer.*`, `certs/inner.*`.

## Exact steps
```bash
# 1. certs
openssl req -x509 -newkey rsa:2048 -nodes -keyout certs/outer.key -out certs/outer.crt -days 365 -subj "/CN=outer-tls"
openssl req -x509 -newkey rsa:2048 -nodes -keyout certs/inner.key -out certs/inner.crt -days 365 -subj "/CN=inner-tls"
# 2. build probe
( cd probe && cargo build --release --target wasm32-wasip1 )
cp probe/target/wasm32-wasip1/release/probe_filter.wasm probe.wasm
# 3. run envoy
podman run -d --name poc2 --entrypoint /usr/local/bin/envoy \
  -v "$PWD/envoy.yaml:/etc/envoy/envoy.yaml:ro" \
  -v "$PWD/probe.wasm:/etc/envoy/probe.wasm:ro" \
  -v "$PWD/certs:/etc/envoy/certs:ro" \
  -p 10000:10000 -p 9901:9901 \
  envoyproxy/envoy:v1.34-latest -c /etc/envoy/envoy.yaml --log-level info
# 4. outer-TLS tunnel + inner-TLS client
socat TCP-LISTEN:11000,fork,reuseaddr OPENSSL-CONNECT:localhost:10000,verify=0 &
curl -sk --http2 https://localhost:11000/nested-tls-works
```

## Observed
curl: `inner-ok`, `http_version=2`, `code=200`.

WASM probe on the internal listener:
```
[INNER-L7] cleartext HTTP seen: method=GET scheme=https path=/nested-tls-works
[INNER-L7] connection.tls_version = "TLSv1.3"
[INNER-L7] connection.requested_server_name = <none>
[INNER-L7] connection.subject_local_certificate = "CN=inner-tls"   <-- inner cert, not outer
[INNER-L7] connection.subject_peer_certificate = <none>
[INNER-L7] connection.mtls = "\0"   (false; no client cert)
```

## Conclusions
- Internal-listener loopback works with a stock image (needed `bootstrap_extensions:
  envoy.bootstrap.internal_listener` — see gotcha below).
- Nested TLS terminates correctly: WASM on the internal listener reads `tls_version=TLSv1.3`
  and `subject_local_certificate=CN=inner-tls` — i.e. it is bound to the **inner** session.
- **OPEN #4 resolved for case 4a** (Envoy is the inner endpoint): the WASM filter CAN see inner
  cleartext, so solution families A and C apply directly. (Case 4b — inner TLS terminating
  inside a separate TEE workload — is a deployment choice, not forced by Envoy.)
- Standard TLS connection properties (`tls_version`, `subject_local_certificate`) ARE exposed
  to WASM. There is **no** RFC 5705 exporter property in this standard set → that's POC 4.

## Gotchas
- `InternalListener bootstrap extension is mandatory` on boot → add the
  `envoy.bootstrap.internal_listener` bootstrap extension (now in `envoy.yaml`).
- Driving TLS-in-TLS: socat supplies the outer tunnel; curl supplies inner TLS + h2 (ALPN).
