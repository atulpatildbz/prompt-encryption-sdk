# POC 5 — Real attestation — RESULTS (local portion) + GCP plan

**Date:** 2026-06-05 · **Env:** MacBook M4 (local crypto path), GCP (real TEE — NOT run)
**Status:** ✅ local crypto path validated · ⬜ real GCA-on-TEE deferred to GCP

## Why the real POC can't run on the M4
A genuine attestation token comes from Google Cloud Attestation (GCA) endorsing a real
Confidential VM (TDX / SEV-SNP). A MacBook has no such TEE, so GCA cannot endorse it. The
hardware root of trust is fundamentally not reproducible locally — only mockable.

## What WAS validated locally (the crypto / binding path)
Installed the SDK into a venv (built the `_ekm.c` OpenSSL extension) and ran the suite:
```bash
python3 -m venv /tmp/pe-venv
CFLAGS=-I$(brew --prefix openssl@3)/include LDFLAGS=-L$(brew --prefix openssl@3)/lib \
  /tmp/pe-venv/bin/pip install -e . pytest pyopenssl starlette uvicorn gunicorn flask fastapi httpx
/tmp/pe-venv/bin/python -m pytest tests/ekm tests/server/attestation_test.py \
  tests/server/keys_test.py tests/client/validator_test.py -q
# => 56 passed, 11 subtests passed, 2 "failed"
```
The 2 "failures" are **environmental, not logic**:
- `attestation_test ... EKMSigned` subtest references a `compare` helper that is **not imported**
  in this OSS checkout (a stripped Google-internal symbol) → `NameError`. The parent test and
  the other subtests pass.
- Both reported failures also hit `OSError: [Errno 9] Bad file descriptor` in pytest's stdout
  flush — a Python 3.14 teardown artifact, unrelated to the SDK.

### Direct confirmation of OPEN #5 (executed, not just code-read)
A standalone script drove `AttestedTLS.attest_connection` with a known EKM + nonce:
```
EKM label/ctx call: ('EXPORTER-Prompt-Encryption-SDK', 32, context=b'client-nonce')
signed.ekm_hash   == sha256(EKM)   : True
signed.token_hash == sha256(token) : True
response binds session_signature   : True
response carries instance pubkey   : True
```
=> The signed `SessionSignaturePayload` **does** bind the live exporter (`ekm_hash`) together
with the attestation-token hash. OPEN #5 resolved AFFIRMATIVE by execution. Exporter-binding
(Solutions C / header-token) is sound, not a replayable bearer token.

## The real GCP POC — plan (to run on a Confidential VM)
1. Provision a GCP Confidential VM (TDX or SEV-SNP) running the workload image.
2. Deploy the SDK server (`AttestedTLS` middleware) behind the chosen topology:
   - **4b (no Envoy patch):** workload terminates inner TLS, does EKM extract + sign (as today).
     Envoy (if present) just forwards inner-encrypted bytes; WASM does connection gating (A2).
   - **4a (WASM owns EKM):** requires the native Envoy exporter extension from POC 4 first.
3. Client runs the SDK validator; confirm it (a) gets a real GCA JWT, (b) verifies the workload
   policy (image hash, hw model), (c) checks `session_signature` over `{ekm_hash, token_hash}`
   against the live inner-TLS exporter.
4. Confirm the ~55-min re-validation cycle and connection churn behave (ties to A2 eviction).

## Workarounds for progressing without a TEE (agreed: "think about how to work around it")
- **Mock attestation** (done in POC 3): exercises the full Envoy/WASM gating control flow with a
  stubbed verdict — no TEE needed.
- **Local crypto path** (done here): real EKM + real signing with a local key; only the GCA
  token is synthetic. Validates everything except the hardware root of trust.
- **Single real CVM**: cheapest real check — one Confidential VM, no full Envoy mesh, to confirm
  the GCA token issuance + client verification end-to-end. Defer the mesh/topology until 4a/4b
  is chosen (POC 4).
