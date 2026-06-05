# POC 3 — Attestation gate (control flow) — RESULTS

**Date:** 2026-06-05 · **Env:** MacBook M4, podman, Envoy `v1.34-latest`
**Status:** ✅ PASS (via A2; A1-from-L7 disproven — see below)

## Goal
Validate the corrected control flow: verdict **born at L7** on `/_attest`, then later streams
on the same connection are gated (allow/reject) per-stream; a fresh connection starts
unattested (fail closed). Decides: does the design need an L4 filter?

## What we learned (the iteration matters)
| Run | Write mechanism (L7) | Result |
|---|---|---|
| #1 | `declare_property` + `set_property(["attested_state"])` | marker did NOT survive to next stream — L7 `set_property` lands in **stream** filter state |
| #2 | `set_envoy_filter_state(span=Connection)` | `ERR NotFound` |
| #3 | `declare_property` then `set_envoy_filter_state` | declare OK, set still `ERR NotFound` (function is for pre-registered *typed* FS objects, not arbitrary WASM names) |
| #4 | **A2: VM-local map keyed by `connection_id`** | ✅ works |

**Conclusion:** A1's connection-lifespan FILTER STATE can only be *written* from **L4** (the
connection context — proven in POC 1). A verdict **born at L7** must instead use **A2**: a
VM-local map keyed by connection id (a connection is pinned to one worker = one single-threaded
WASM VM, so no lock is needed).

## Final passing run (A2)
Filter: `gate/src/lib.rs` (thread-local `HashSet<u64>` of attested `connection_id`s).
Drive (curl reuses one h2 connection across URLs in a single invocation):
```bash
curl -s --http2-prior-knowledge http://localhost:10000/app-before \
  http://localhost:10000/_attest http://localhost:10000/app-after http://localhost:10000/app-after2
curl -s --http2-prior-knowledge http://localhost:10000/app-fresh   # fresh connection
```
Observed:
```
/app-before  -> 403   [GATE] REJECT conn_id=1 (not attested)
/_attest     -> 200   [GATE] /_attest -> conn_id=1 marked attested (A2 VM-local map)
/app-after   -> 200   [GATE] ALLOW  conn_id=1 (attested)
/app-after2  -> 200   [GATE] ALLOW  conn_id=1 (attested)
/app-fresh   -> 403   [GATE] REJECT conn_id=2 (not attested)   <- fresh conn, new id
```
`connection_id` property is readable from L7 (LE u64), stable per connection, monotonic
(1, then 2) — usable as the A2 map key.

## Implications for the design
- **No L4 filter is required** for an L7-born verdict — use A2.
- If you specifically want A1 (Envoy-owned connection-lifespan state, auto-GC), the WRITE must
  happen at L4; that means either gating attestation at L4 (Solution B) or having L4 learn the
  verdict some other way. For the SDK's HTTP `/_attest`, A2 is the natural fit.
- **A2 caveat (known):** the map leaks one entry per closed connection unless cleaned up. A
  pure-L7 filter has no connection-close hook; production needs an L4 `StreamContext::on_done`
  (or a network filter) to evict, or accept a bounded leak sized by concurrency. Not addressed
  in this POC.

## Gotchas
- L7 `set_property` of a "Connection"-declared property does NOT propagate across streams.
- `set_envoy_filter_state` returns `NotFound` for arbitrary WASM blob names (typed FS only).
