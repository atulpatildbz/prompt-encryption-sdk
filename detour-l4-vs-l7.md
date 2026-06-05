# Learning detour: L4 (network) vs L7 (HTTP) filters in Envoy — and their roles in the "A1" attestation solution

> **How to use this file:** paste the "Briefing" section below into a **fresh AI
> conversation**. The "Reference map" and "Key facts" sections give that agent all
> the context and source pointers it needs — it starts with zero memory of the
> project, so everything it requires is either here or linked from here.

---

## Briefing (paste this into the new conversation)

I'm learning **how Envoy gates traffic by connection-attestation status (the "A1"
solution)** and hit **the division of labor between L4 and L7 filters**, which I
don't understand well enough yet. I want to solidify this base concept first.

**Where it showed up:** The "A1" design is described as: *an L4 network filter
writes an "attested" marker into connection-scoped state once per connection, and
an L7 HTTP filter reads that marker on every request to allow or block it.* I keep
losing track of which layer does what and why it has to be split that way.

**Why it matters to the parent:** A1's entire mechanism is split across the two
layers — L4 produces the verdict tag, L7 consumes it. If I don't understand what
each layer can see, when it fires, and why only L4 can write connection-scoped
state, A1 just looks like arbitrary rules.

**Where I'm starting from:** I know Envoy is a proxy and I understand the
"per-connection vs per-request" problem at a high level. I'm fuzzy on what an L4
filter actually does vs an L7 filter, when each runs, and the read/write asymmetry.

**What I need to walk away understanding:**
1. What an L4 (network) filter vs an L7 (HTTP) filter can each *see* and *do*, and
   *when* each fires in a connection's life.
2. In A1 specifically: which filter writes the "attested" tag, which reads it, and
   the order of events for a connection carrying several requests.
3. *Why* only L4 can write connection-scoped state (and L7 can only read it) — the
   underlying reason, not just the rule.

**How to teach me:** Use the `feynman-learning` skill. Explain it clearly, then let
me explain it back so we can catch gaps. Teach L4/L7 filters as their own thing
first, then connect to A1.

(When I understand this, I'll return to: **the A1 connection-attestation solution
for Envoy nested-TLS**.)

---

## Key facts already established (verify, don't just trust)

- Envoy is a proxy with two relevant filter types:
  - **L4 = network filter** — fires **once per connection** (`on_new_connection`),
    operates at the raw TCP/connection level. Its filter state *is* the connection's.
  - **L7 = HTTP filter** — fires **per request/stream** (one HTTP/2 connection carries
    many requests), operates at the HTTP level. Its filter state is *per request*.
- Problem solved by A1: attestation is a **per-connection** fact; requests are handled
  **per-request**; a per-request filter has no built-in signal of whether its connection
  was attested.
- **A1** = store the verdict as **connection-scoped (DownstreamConnection-lifespan)
  filter state**, written via the `declare_property` foreign function. Envoy auto-deletes
  it on connection close.
- **POC-proven asymmetry (the crux):** only the **L4** filter can *write* the
  connection-scoped tag. When **L7** writes it, the value lands in *per-request* scope and
  disappears on the next request (`set_property` from L7 → stream scope;
  `set_envoy_filter_state` → `NotFound` for arbitrary names). **L7 *can read* the
  connection tag fine** (a request can look "up" to its connection).
- Consequence: attestation in the SDK is an **HTTP exchange** (`/_attest-connection`) = L7,
  so the verdict is "born" at L7 — but A1 needs the write at L4. That mismatch is why the
  project pivoted to **A2** (an in-memory map keyed by connection id, written+read at L7).
  *Learn A1 first; A2 is the follow-up.*

---

## Reference map (all project context for a fresh agent)

Working dir: `/Users/atul/code/prompt-encryption-sdk`

**Design & decisions**
- `brainstorm.md` — the original design handoff. Solutions **A1/A2/B/C**, the **OPEN
  items**, and **VERIFIED** findings traced through Envoy source. Read §2 (the core
  problem), §3 (candidate solutions), §4 (verified A1 is config-only WASM).

**Experiment results (run 2026-06-05 on a MacBook M4 via podman)**
- `POC-log.md` — index of all 5 POCs, verdicts, env gotchas, and a "bottom line" section.
- `poc/poc1-filterstate/` — **A1 keystone proof.** `README.md`, `src/lib.rs` (L4 writes
  connection-lifespan marker, L7 reads per stream), `envoy.yaml`. PASS.
- `poc/poc2-nested-tls/RESULTS.md` — nested TLS (TLS-in-TLS) terminates inside Envoy; WASM
  sees inner cleartext. PASS.
- `poc/poc3-gating/RESULTS.md` — **MOST RELEVANT to this detour.** Shows the L4-write /
  L7-read asymmetry empirically, and why a verdict born at L7 must use A2 not A1.
- `poc/poc4-ekm/RESULTS.md` — the inner TLS RFC-5705 exporter (EKM) is NOT exposed to WASM
  on a stock Envoy; needs a custom Envoy build. NEGATIVE finding.
- `poc/poc5-gcp/RESULTS.md` — SDK crypto path validated locally; real GCA-on-TEE deferred to
  GCP. Confirms the signed bundle binds the live EKM.

**Learning progress**
- `.feynman-learning-log.md` — what's been learned + this detour's return path.

**SDK source (the "current" / old solution being enhanced)**
- `src/prompt_encryption_sdk/server/attestation.py` — `attest_connection`: extracts EKM,
  signs `SessionSignaturePayload{ekm_hash, token_hash}` with the instance key (≈ lines 103-111).
- `src/prompt_encryption_sdk/server/asgi.py` — routes `/_attest-connection` (the L7 attest
  endpoint, ≈ line 71).
- `src/prompt_encryption_sdk/proto/attestation.proto` — `SessionSignaturePayload` (binds EKM
  to the TLS session) and `AttestConnectionResponse` (≈ lines 46-65).
- `src/prompt_encryption_sdk/ekm/_ekm.c` — C ext calling OpenSSL `SSL_export_keying_material`.

**Envoy source (the evidence behind A1 — replace `main` with your pinned tag)**
- declare_property / set_envoy_filter_state foreign fns:
  `source/extensions/common/wasm/foreign.cc`
- lifespan + WasmType enums, `DeclarePropertyArguments`:
  `source/extensions/common/wasm/ext/declare_property.proto`
  (verified: `WasmType.Bytes=0`; `LifeSpan.DownstreamConnection=2`; fields name=1, type=3, span=5)
- read path traverses connection→stream: `source/extensions/common/wasm/context.cc`
- CI proof of the DownstreamConnection declare/set/get round trip:
  `test/extensions/filters/http/wasm/test_data/test_cpp.cc`

**Proxy-Wasm SDK (how the filters are written)**
- Rust SDK: https://github.com/proxy-wasm/proxy-wasm-rust-sdk (the POCs use this)
- ABI spec: https://github.com/proxy-wasm/spec
