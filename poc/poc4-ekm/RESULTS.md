# POC 4 — EKM / TLS-exporter readability from WASM — RESULTS

**Date:** 2026-06-05 · **Env:** MacBook M4, podman, Envoy `v1.34-latest`, nested-TLS (reuses
POC 2 topology + certs; inner TLS = TLSv1.3 terminating inside Envoy).
**Status:** ✅ investigation COMPLETE — finding is NEGATIVE (exporter not exposed). Custom-build
remedy NOT executed (heavy; see below).

## Goal
Resolve OPEN #3: can a WASM filter read the inner TLS RFC 5705 keying-material exporter
(the SDK's attestation binding, label `EXPORTER-Prompt-Encryption-SDK`) at stream scope?

## Method
Probe filter (`probe/src/lib.rs`) on the inner listener enumerates the documented `connection`
attributes and also tries exporter/EKM-style names. Driven via the POC 2 nested-TLS path.

## Observed (curl 200 / h2)
Readable from WASM:
```
connection.id                       = <8-byte LE conn id>
connection.mtls                     = false
connection.tls_version              = "TLSv1.3"
connection.subject_local_certificate= "CN=inner-tls"   (inner cert)
```
`<none>` (no client cert / not enabled): subject_peer_certificate, dns/uri SANs,
sha256_peer_certificate_digest, ja3_fingerprint, ja4_fingerprint, termination_details.

Exporter/EKM probes — **ALL absent**:
```
ekm, exported_keying_material, keying_material, tls_exporter, exporter, tls_keying_material
   -> present=false (both connection.<name> and bare <name>)
```

## Conclusion (OPEN #3 resolved: NO)
Stock Envoy exposes a **fixed** set of TLS connection attributes to WASM; **none** is an
RFC 5705 keying-material exporter, and there is no way to call `SSL_export_keying_material`
with a custom label/context from WASM. So a WASM filter **cannot** read the inner exporter
out of the box.

**Important — "extension" ≠ config-only.** Three tiers:
1. Config-only (WASM / Lua / standard filters on the STOCK image, YAML only) → CANNOT get EKM.
2. Native C++ extension compiled into Envoy (Bazel build of a CUSTOM binary) → CAN, but this
   IS a change to the Envoy binary, not config-only.
3. Core patch/fork → CAN (heaviest).
EKM extraction needs tier 2 at minimum: a custom Envoy build. The stock official image cannot
do it with any amount of configuration. (Evidence is strong but not an exhaustive survey of
every contrib filter/version — verify against the exact target build.)

## Why this matters — it forces the OPEN #4 architecture choice
The inner EKM belongs to whoever terminates the inner TLS:
- **Case 4a — Envoy terminates inner TLS** (what POCs 2/4 do; cert = Envoy's `CN=inner-tls`).
  The EKM lives in Envoy. For WASM to bind attestation to it you must **expose the exporter to
  WASM via a native Envoy extension/patch** (call `SSL_export_keying_material` and surface it as
  a property or foreign function). This is a C++/Bazel build of Envoy — **NOT done here**
  (hours, heavy; do on Linux/cloud). The WASM ABI itself is fine; this is an Envoy-side add.
- **Case 4b — the TEE workload terminates inner TLS** (Envoy forwards inner-encrypted bytes).
  Then the **workload** extracts the EKM and signs — exactly what the SDK does today
  (`src/.../ekm/_ekm.c` -> `SSL_export_keying_material`, `server/attestation.py`). No Envoy
  patch. But then WASM can't see inner cleartext, so any WASM gating must run on a
  connection-level signal, not the inner HTTP.

## Recommendation
- If attestation/signing stays in the workload (4b, least change): **no Envoy patch needed**;
  Envoy/WASM only does connection gating (POC 3 / A2). Cleanest near-term path.
- If you want WASM to own attestation AND bind to the inner EKM (4a): budget a small native
  Envoy extension to expose the exporter. That is the only blocker; everything else (A1/A2,
  loopback, gating) is config-only WASM as proven in POCs 1–3.

## Not executed (out of local scope)
Building a custom Envoy with an exporter-exposing extension — requires Bazel/C++ toolchain and
significant build resources; recommended on a Linux build host, not the M4.
