# POC Log — Envoy Nested-TLS Attestation (stream-scope problem)

Tracking experiments that validate the Envoy/WASM enhancement to the prompt-encryption SDK.
See `brainstorm.md` for the design and OPEN items; `.feynman-learning-log.md` for the conceptual model.

**Goal of POCs:** prove the A1 mechanism (attestation verdict born at L7, stored at
connection-lifespan filter state, read per-stream to gate) on the actual target Envoy,
and surface the cost of the risky OPEN items before committing.

---

## Environment feasibility (MacBook M4 / arm64)

| Component | Local on M4? | How |
|---|---|---|
| Envoy | ✅ native | Official `envoyproxy/envoy` multi-arch image via Docker Desktop (`linux/arm64`), no emulation |
| WASM filter (Rust) | ✅ | Rust → `wasm32-wasip1`; arch-neutral bytecode. Use Rust proxy-wasm SDK (not C++) |
| SDK workload (Python) | ✅ | Pure Python + small C ext for EKM |
| Conn-lifespan filter-state round trip | ✅ | Config-only WASM, stock image |
| Nested-TLS loopback (`internal_upstream_transport`) | ✅ | Config-only |
| Custom EKM exporter readable *from WASM* (OPEN #3) | ⚠️ maybe / costly | May need custom Envoy build (Bazel from source) — do on Linux/cloud, not Mac |
| Real GCA attestation token from genuine TEE | ❌ | Needs GCP Confidential VM (TDX/SEV); mock locally |

**Hard boundary:** Envoy plumbing + binding logic = testable locally. Anything needing a
*real attestation report* = mock locally, validate on GCP later. (GCP workaround: TBD.)

---

## POC ladder

Status legend: ⬜ not started · 🟡 in progress · ✅ passed · ❌ failed/blocked

### POC 0 — Environment sanity ⬜
- **Objective:** stock arm64 Envoy in Docker, trivial passthrough config, proxies HTTP/2.
- **Validates:** toolchain only.
- **Local:** ✅
- **Findings:** _(pending)_

### POC 1 — Connection-lifespan filter-state round trip (KEYSTONE) ✅ PASSED (2026-06-05)
- **Objective:** Rust WASM filter writes a `DownstreamConnection`-lifespan marker via
  `declare_property` foreign function; reads it per-stream at L7. Drive many HTTP/2 streams
  on one connection, then a fresh connection.
- **Validates:** OPEN #1 (foreign fns in image), OPEN #2 (lifespan enum in tag), and the
  whole A1 premise (one write amortizes; fresh conn reads absent).
- **Expected:** marker present+stable across streams on same conn; "absent" on fresh conn.
- **Local:** ✅
- **Scaffold:** `poc/poc1-filterstate/` — Rust filter (`src/lib.rs`), `envoy.yaml`
  (:10000 write+read / :10001 read-only control), `run.sh`, `drive.sh`, README.
  Run not yet executed (needs Docker + Rust + h2load on the M4).
- **Verified-while-building (ABI, from Envoy `main` declare_property.proto):**
  - `WasmType`: Bytes=**0**, String=1, FlatBuffers=2, Protobuf=3  (Bytes is 0, not 2!)
  - `LifeSpan`: FilterChain=0, DownstreamRequest=1, DownstreamConnection=2
  - `DeclarePropertyArguments`: name=1(string), readonly=2(bool), **type=3**(WasmType),
    schema=4(bytes), **span=5**(LifeSpan)  ← type/span are fields 3/5, not 2/3.
  - CI (`test_cpp.cc`) reads a declared prop via the bare name path `{"structured_state"}`,
    so POC reads `["attested_state"]`; fallback `["filter_state","attested_state"]` if ABSENT.
- **RESULT (PASS), Envoy v1.34-latest, official image, podman on M4:**
  - A (1 conn × 3 streams, :10000): **1** `[L4]` write, **3** `[L7]` reads all `attested-marker-v1`.
  - B (2nd conn, :10000): another `[L4]` write → per-connection scoping confirmed.
  - C (:10001, no write filter): **0** writes, all `[L7]` reads `ABSENT` → fails closed.
  - => OPEN #1 (foreign fns present) and OPEN #2 (DownstreamConnection lifespan) CLOSED.
    A1 is config-only WASM, no Envoy fork, on stock official image. Read path `["attested_state"]`
    worked (no `["filter_state",...]` fallback needed). Cross-root sharing (writer root → reader
    root, same vm_id, via connection filter state) works.
- **Env gotchas hit & fixed (for reproducibility):**
  1. Homebrew `rust` is broken (LLVM symbol mismatch). Use the rustup toolchain:
     `export PATH="$HOME/.cargo/bin:$PATH"`.
  2. Rootless podman + envoyproxy/envoy entrypoint fails on `chown /dev/stdout`.
     Fix: `--entrypoint /usr/local/bin/envoy`.
  3. `get_type()` returning `None` panics the proxy-wasm dispatcher (`unreachable`,
     dispatcher.rs:201). Fix: one module, two `root_id`s; branch mode on plugin
     `configuration` ("write"/"read") and return a concrete `ContextType`.
  4. No `h2load`; drove multi-stream-one-conn with `curl --http2-prior-knowledge <url> <url> ...`.

### POC 2 — Nested-TLS loopback ✅ PASSED (2026-06-05)
- **Objective:** two-listener config; outer TLS on public listener →
  internal-listener loopback → inner TLS terminates on internal listener.
  Confirm bytes flow and inner TLS terminates *inside Envoy*.
- **Validates:** topology + much of OPEN #4 (can WASM see inner cleartext?).
- **Local:** ✅
- **Detail:** `poc/poc2-nested-tls/RESULTS.md` (full commands + raw logs).
- **RESULT (PASS):** nested-TLS drive via `socat`(outer tunnel)+`curl`(inner TLS+h2) →
  200/`inner-ok`. WASM probe on internal listener logged cleartext `path=/nested-tls-works`,
  `tls_version=TLSv1.3`, `subject_local_certificate=CN=inner-tls` (the INNER cert) → proves
  WASM is bound to the inner session and sees decrypted HTTP.
  => OPEN #4 resolved for case 4a (Envoy = inner endpoint): families A/C apply directly.
  Standard TLS props exposed to WASM; NO RFC 5705 exporter property in the standard set (→POC 4).
- **Gotcha:** internal listeners need `bootstrap_extensions: envoy.bootstrap.internal_listener`.

### POC 3 — Gating logic end-to-end, mocked attestation ✅ PASSED (2026-06-05)
- **Objective:** L7: on `path==/_attest` run stub attestation → mark connection attested;
  other paths → gate. Sequence: unattested rejected → /_attest marks → later streams allowed
  → fresh conn rejected.
- **Validates:** corrected control flow (verdict born at L7, gate reads per-stream).
- **Local:** ✅ (full mechanism minus real crypto)
- **Detail:** `poc/poc3-gating/RESULTS.md`.
- **RESULT (PASS via A2):** /app-before→403, /_attest→200(mark conn_id=1), /app-after(+2)→200,
  fresh conn_id=2→403. `connection_id` readable from L7 (LE u64, monotonic) → A2 map key.
- **KEY FINDING (decision #1 resolved):** A1's connection-lifespan FILTER STATE can only be
  *written* from L4. L7 `set_property` lands in stream scope (doesn't survive next stream);
  `set_envoy_filter_state` → NotFound for arbitrary WASM names. So a verdict born at L7 must
  use **A2 (VM-local map keyed by connection_id)**, NOT A1. Pure-L7 works with A2 → no L4
  filter required.
- **A2 caveat:** map leaks 1 entry/closed-conn; pure-L7 has no close hook. Prod needs L4
  on_done evict or bounded-leak acceptance.

### POC 4 — EKM readability from WASM (RISK SPIKE) ✅ INVESTIGATED — NEGATIVE (2026-06-05)
- **Objective:** read inner TLS exporter (custom label `EXPORTER-Prompt-Encryption-SDK`)
  from WASM. Try stock Envoy + standard TLS properties first; if insufficient, measure
  cost of custom Envoy build.
- **Validates:** OPEN #3. Forces trust-boundary decision.
- **Detail:** `poc/poc4-ekm/RESULTS.md`.
- **RESULT (OPEN #3 = NO):** stock Envoy exposes a FIXED set of TLS attrs to WASM
  (tls_version, subject_local_certificate, id, mtls readable). NO exporter/EKM property —
  all of {ekm, exported_keying_material, keying_material, tls_exporter, exporter,
  tls_keying_material} absent. WASM cannot call SSL_export_keying_material out of the box.
- **Forces OPEN #4 choice:**
  - 4a Envoy terminates inner TLS → EKM in Envoy → need a native Envoy extension/patch to
    expose exporter to WASM (C++/Bazel build — NOT done locally; heavy).
  - 4b Workload terminates inner TLS → workload extracts+signs EKM (as SDK does today,
    ekm/_ekm.c + server/attestation.py) → no Envoy patch; WASM only gates (A2).
- **Recommendation:** 4b for least change (no patch); 4a only if WASM must own EKM binding.
- **Not executed:** custom Envoy build (do on Linux/cloud).

### POC 5 — Real attestation ✅ local crypto path DONE · ⬜ real-TEE deferred (2026-06-05)
- **Objective:** wire real `attest_connection` against a real GCA token on a Confidential VM.
- **Validates:** OPEN #4 (where inner TLS terminates) + hardware root of trust + OPEN #5.
- **Local:** crypto path ✅ (real EKM+signing, synthetic GCA token); real TEE ❌ (GCP only).
- **Detail:** `poc/poc5-gcp/RESULTS.md`.
- **RESULT (local):** SDK suite 56 passed + 11 subtests (2 "fails" = env: missing `compare`
  helper + Py3.14 fd-flush, NOT logic). Direct script confirmed OPEN #5 by execution: signed
  payload `ekm_hash==sha256(EKM)` AND `token_hash==sha256(token)`; EKM pulled with label
  `EXPORTER-Prompt-Encryption-SDK` + client nonce as context. Exporter-binding is sound.
- **Real GCP plan:** provision Confidential VM (TDX/SEV-SNP) → deploy SDK server (topology per
  4a/4b from POC 4) → client validates GCA JWT + policy + session_signature vs live exporter →
  check ~55-min re-validation + churn (A2 eviction). Workarounds: mock (POC 3) / local crypto
  (done) / single real CVM for cheapest end-to-end.
- **Build note:** `_ekm.c` needs `CFLAGS=-I$(brew --prefix openssl@3)/include` etc.; py deps
  starlette/uvicorn/gunicorn/pyopenssl/flask/fastapi/httpx. venv at /tmp/pe-venv.

---

## Open decisions to lock as POCs resolve them
1. L4 filter needed at all, or pure L7? (POC 3 decides)
2. Where does the signing key live — WASM or workload? (POC 4 forces)
3. GCP access workaround for POC 5.

## Running findings summary
- 2026-06-05: POC 1 PASS. Connection-lifespan filter-state write (L4) → per-stream read (L7)
  on stock Envoy v1.34, config-only WASM. OPEN #1 + #2 closed.
- 2026-06-05: POC 2 PASS. Nested-TLS loopback; WASM on internal listener sees inner cleartext
  + inner cert (CN=inner-tls). OPEN #4 case 4a confirmed (Envoy can be inner endpoint).
- 2026-06-05: POC 3 PASS (A2). L7-born verdict gates per-stream via VM-local map keyed by
  connection_id. KEY: A1 conn-state writable only from L4; pure-L7 must use A2. No L4 needed.
- 2026-06-05: POC 4 NEGATIVE (decisive). No RFC-5705 exporter exposed to WASM in stock Envoy.
  Forces OPEN #4 choice: 4b (workload signs EKM, no patch) vs 4a (native Envoy exporter ext).
- 2026-06-05: POC 5 local crypto path DONE; OPEN #5 confirmed by execution (signature binds
  sha256(EKM)+sha256(token)). Real TEE on GCP deferred (no local TEE).

## Bottom line after POCs 1–5
The Envoy/WASM enhancement is mechanically sound and config-only for the hard parts (loopback,
connection-scoped gating, nested-TLS termination) — all proven on the M4. Two real decisions
remain, both surfaced by the POCs:
  1. Where inner TLS terminates (4a Envoy vs 4b workload) — gates whether you need a native
     Envoy exporter extension at all. 4b = least change.
  2. A2 map eviction on connection close (needs an L4 on_done hook or bounded-leak acceptance).
Everything else is validated. Real GCA-on-TEE is the only piece that must move to GCP.
