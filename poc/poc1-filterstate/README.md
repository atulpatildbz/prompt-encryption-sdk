# POC 1 — Connection-lifespan filter-state round trip (keystone)

Proves the A1 mechanism on the target Envoy: an **L4 network filter** writes a marker at
`DownstreamConnection` lifespan; an **L7 HTTP filter** reads it back **per stream**. If this
works, one attestation can amortize across all streams on a connection — config-only WASM,
no Envoy fork. Validates brainstorm OPEN #1 (foreign fns present) and #2 (lifespan enum).

## Prerequisites (MacBook M4)
- Docker Desktop (pulls `linux/arm64` Envoy natively — no emulation)
- Rust + `rustup` (`cargo build` adds the `wasm32-wasip1` target automatically via `run.sh`)
- `h2load` for the driver: `brew install nghttp2`

## Run
```bash
./run.sh        # terminal 1: builds the .wasm, starts Envoy, streams logs
./drive.sh      # terminal 2: sends HTTP/2 traffic
```
Watch terminal 1 for `wasm log` lines tagged `[L4]` and `[L7]`.

## Expected result (PASS)
| Driver step | Connections × streams | Expect in Envoy log |
|---|---|---|
| A (:10000) | 1 × 10 | **1** `[L4]` write, **10** `[L7] ...attested=attested-marker-v1` |
| B (:10000) | 2 × (10) | **2** `[L4]` writes, all `[L7]` reads PRESENT |
| C (:10001) | 1 × 5 | **0** `[L4]` writes, all `[L7] ...attested=ABSENT` |

A+B show the marker is written **once per connection** and survives across streams (lifespan
is genuinely `Connection`, not per-stream). C is the control: with no writer, reads are ABSENT
— i.e. the gate fails closed, which is the whole point.

## What each outcome tells us
- **All as expected** → A1 is real on this build. Close OPEN #1 and #2. Proceed to POC 2.
- **`declare_property FAILED`** in `[L4]` → foreign functions not in this image (OPEN #1). Try
  the official non-distroless image / a newer tag.
- **Reads ABSENT even on :10000** → the marker didn't persist at connection scope. Likely the
  set/read path or the declare encoding. Things to try, in order (record which works in POC-log):
  1. read path `["filter_state", "attested_state"]` instead of `["attested_state"]`
  2. also call `declare_property` on the read (L7) side before reading
  3. verify your Envoy tag's `declare_property.proto` field numbers match `src/lib.rs`

## TROUBLESHOOTING — `[L7]` never logs at all
`get_type()` returns `None` so one module serves as both filter types. If the HTTP context
isn't created on your build, split into two `.wasm` modules (one implementing only
`create_stream_context`, one only `create_http_context`), or branch on plugin `configuration`
("write"/"read") in `on_configure`. Note the workaround in POC-log.

## Knobs
- `ENVOY_IMAGE=envoyproxy/envoy:vX.Y-latest ./run.sh` — **pin to your target tag** (OPEN #2).
- `WASM_TARGET=wasm32-wasi ./run.sh` — fallback if your toolchain lacks `wasm32-wasip1`.
