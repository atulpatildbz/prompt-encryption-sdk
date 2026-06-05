# Handoff: Nested-TLS Attestation on Envoy — Stream-Scope Problem

**Purpose of this doc.** Hand this to an AI agent (or engineer) so they can (a) understand the problem we're solving, (b) pick up the design decisions and *verified* findings we've already nailed down, and (c) either explain it back, run experiments, or continue ideation without re-deriving everything. Sections marked **VERIFIED** are backed by Envoy source/tests (links in-line); sections marked **ASSUMPTION** or **OPEN** still need confirmation.

---

## 1\. What we're building

We are enhancing Google's prompt-encryption SDK by putting **Envoy** in front of the TEE (Trusted Execution Environment) workload and implementing **nested TLS** ("TLS-in-TLS"):

- **Inner TLS** — the real end-to-end security boundary, between the *end nodes* (client ↔ TEE endpoint). This is the channel that gets **attested**, via a TLS keying-material exporter binding (RFC 5705 style; the SDK uses an exporter label like `EXPORTER-Prompt-Encryption-SDK`). The attestation proves the channel terminates inside a genuine TEE and binds that proof to *this specific TLS session*.  
- **Outer TLS** — hop-by-hop transport only. It **may terminate on untrusted intermediate nodes** (LBs, mesh hops). It can be re-established and pooled independently.

Mechanics in Envoy:

- Outer TLS terminates on the public listener.  
- Decrypted bytes (still inner-TLS-encrypted) are looped back into Envoy via the **internal listener** ("loopback") feature — userspace sockets, no kernel round trip.  
- The **inner TLS** session terminates on the internal listener.  
- A **WASM filter** *performs / assists* the attestation (it is an active participant in the attestation handshake, not just a passive reader of a verdict).

Rough topology:

client ──outer TLS──\> \[untrusted intermediates\] ──\> Envoy public listener (outer TLS terminates)

        └─ inner TLS (end-to-end, attested) ───────────────────────────────┐

                                                                            v

                              internal\_upstream\_transport (loopback) ──\> internal listener

                                                                            │ inner TLS terminates

                                                                            v

                                                            WASM attestation filter(s)

                                                                            v

                                                                       TEE workload

---

## 2\. The core problem (why this doc exists)

**Filter-state lifetime / scope mismatch between connection and stream.**

- Attestation is a **per-connection** fact, bound to the inner TLS exporter. It is established once, at connection establishment.  
- But traffic is processed **per-stream**. On HTTP/2 the inner connection multiplexes many request streams, each with its own `StreamInfo`.  
- A WASM filter running at **stream scope** has no inherent signal of:  
  1. *which* inner connection the stream rode in on, or  
  2. whether that connection has cleared attestation.

So, in the problem owner's words: *"there's no information of whether a stream is coming on an attested connection or a new connection."*

Why it can't be a global "attested \= true" flag: new connections appear continuously and must be treated as **unattested until proven** — client churn, HTTP/2 GOAWAY, connection-pool growth, and the SDK's periodic re-validation (\~55 min). The gate must be strictly **per-inner-connection**, yet readable from **stream scope**.

**Trust-model constraint (important):** because outer TLS can terminate on untrusted intermediates, **no signal derived from the outer layer may be used as an attestation verdict.** Even though `internal_upstream_transport` *will* copy shared filter-state from the outer/downstream connection across the loopback, that data is usable only for *correlation/logging*, never as the trust verdict. The verdict must be born at the inner layer and anchored to the inner connection.

---

## 3\. Candidate solutions

### A1 — Connection-lifespan filter state (Envoy owns the lifetime) — **RECOMMENDED**

- L4 WASM **network** filter fires once per inner connection (`on_new_connection`), drives attestation, and on success writes an "attested" object at **Connection lifespan**.  
- L7 WASM **HTTP** filter (same `vm_id`) reads that object per stream. Present+valid → allow; absent → not attested → reject / trigger attestation.  
- Envoy destroys the object on connection close — **no manual cleanup code**.

### A2 — VM-local map keyed by connection id (you own the lifetime) — portable fallback

- L4 filter attests, stores `conn_id → verdict` in a **module-global map** in the worker's WASM VM.  
- Because a downstream connection is pinned to **one worker thread \= one WASM VM** for its whole life, and a WASM VM executes single-threaded, this map needs **no lock** and has no cross-thread contention. (Do **not** use cross-VM `proxy_shared_data` — wrong scope, unnecessary.)  
- Per-stream cost \= one lock-free map lookup. Attestation cost amortizes across all streams.  
- **Catch:** you must delete the entry on connection close (`on_done`/`on_delete`) or the map leaks. Conn-id reuse is not a concern (Envoy ids are monotonic uint64 per process).

### Scaling note (resolves an early worry)

"Shared memory list of all attested connections" was a mischaracterization. It's an O(1) hashmap of *currently-live* attested connections (sized by concurrency, not throughput; a few dozen bytes/entry), per-worker, lock-free. Memory was never the bottleneck. A1 and A2 have identical scaling profiles; A1 just removes the bookkeeping you can get wrong.

### B — Gate at L4 so unattested connections never emit streams

- If the connection is blocked at the network filter until attestation passes, every HTTP stream that reaches L7 is attested *by construction*; L7 needs no knowledge. **Tension:** the SDK's attestation is itself an HTTP exchange (`/_attest-connection`, i.e. L7), so pure-L4 gating forces moving attestation earlier (custom ALPN / pre-HTTP sub-protocol bound to the exporter). Cleaner runtime, bigger protocol change.

### C — Stateless per-stream re-binding via the exporter (defense-in-depth)

- Each stream cheaply re-verifies that the cached token is bound to **this** connection's exporter. Doesn't escape needing connection identity (streams on one connection share one exporter), but hardens against connection-confusion / pool-reuse. Pair with A2's cache (verify-once, re-bind-cheaply).

### The "send token in header" idea — analyzed

Forcing the client to echo a token header on every request:

- **A bare bearer token does NOT work** — it decouples trust from the channel; any untrusted client who obtains it can replay it on an un-attested connection. (This is the reuse worry, and it's real.)  
- **A connection-bound token DOES work** — bind the token to the inner TLS exporter (DPoP / mTLS-bound-token pattern, **RFC 9449 / RFC 8705**). The filter re-verifies per request that the presented token is bound to *this* connection's exporter; a replayed token has a different exporter → fails.  
- **The decisive question for the existing scheme:** the SDK reportedly doesn't send the OIDC token raw — it "pairs it with something and sends a signature of the bundle." **Does that signed bundle cover the live exporter value?** If yes → sound, and it makes the stream-scope problem *vanish* (every request self-describes its status; server can be near-stateless per connection). If the signature covers only OIDC-token \+ static material → still effectively a bearer token → replayable. **→ ACTION: confirm what the bundle signs.**  
- Threat-model caveat: exporter binding stops *leak-to-third-party* replay completely. It does **not** stop a *legitimately-attested-but-malicious* client misusing its own connection — no scheme does; that's inherent to "attest the channel, then trust the channel," not a regression.  
- Cost of the token approach: a signature verify per request (vs a map lookup), a client-contract change, and it requires the filter to **read the inner TLS exporter at stream scope** (see OPEN items).

---

## 4\. VERIFIED findings (traced through Envoy source \+ CI, not memory)

**Question settled:** *Can a WASM filter write Connection-lifespan filter state and read it back from the HTTP (per-stream) context — config-only, no Envoy fork / native extension / binary change?*

**Answer: YES. A1 is config-only WASM.** Evidence chain (Envoy `main`):

1. **Foreign functions exist on the WASM-facing ABI.** Envoy registers `declare_property` and `set_envoy_filter_state` as foreign functions callable from any WASM module via `proxy_call_foreign_function`. `source/extensions/common/wasm/foreign.cc`  
2. **Connection lifespan is an explicit option.** The proto enum exposed to WASM is `FilterChain = 0`, `DownstreamRequest = 1`, `DownstreamConnection = 2`; `foreign.cc` maps `DownstreamConnection → StreamInfo::FilterState::LifeSpan::Connection`. `source/extensions/common/wasm/ext/declare_property.proto`  
3. **The read path traverses connection→stream automatically.** WASM property reads resolve filter state via `getRequestStreamInfo()->filterState()`; the HTTP stream filter state has the connection filter state as an ancestor, so a per-stream read of a `Connection`\-lifespan object succeeds. (This is the fallback that historical envoy-wasm issue \#402 was about; it exists in current code.) `source/extensions/common/wasm/context.cc`  
4. **Envoy's own CI proves the round trip.** A WASM test module declares a property with `DownstreamConnection` lifespan, sets it, and reads it back via the `filter_state` property. `test/extensions/filters/http/wasm/test_data/test_cpp.cc` (\~line 665\)

**The catch that replaces the old doubt:** lifespan control is **not** in the convenience property API. `proxy_set_property(["filter_state", key], val)` writes at the **default `FilterChain`** lifespan (`context.cc` `setProperty` uses `prototype.life_span_`, default `FilterChain`). To get Connection lifespan you must call the **foreign function** `declare_property` (and/or `set_envoy_filter_state`) with a serialized protobuf payload (`DeclarePropertyArguments` / `SetEnvoyFilterStateArguments`). That's a small, lower-level WASM detail — available in the C++ and Rust proxy-wasm SDKs — **not** an Envoy change.

**Net effort for A1 (config-only):**

- Use a standard Envoy build that ships the WASM foreign functions (official builds do).  
- L4 network filter: after attestation succeeds, call `declare_property("attested", span=DownstreamConnection)` once, then set the value (verdict / token-hash).  
- L7 HTTP filter (same `vm_id`): per stream, `getValue({"filter_state", "wasm.attested"})`.  
- Envoy frees the object on connection close. No map, no `on_done` cleanup.

---

## 5\. OPEN items — verify against the *target* build (none are code changes)

1. **Foreign functions present in your image.** Official Envoy ships them; some minimal/custom/ stripped builds disable extensions. Quick grep/test against your image.  
2. **Version skew.** Findings above are from `main`. If pinned to an older release, confirm `DownstreamConnection` is in that tag's `declare_property.proto` (it has been there for years).  
3. **Inner TLS exporter readable from WASM at stream scope?** Standard TLS connection properties are exposed to WASM, but a **custom RFC 5705 keying-material exporter** (label `EXPORTER-Prompt-Encryption-SDK`) may not be exposed out of the box. This is load-bearing for the token/exporter-binding approach (Solution C and the header-token idea). **Needs confirmation.**  
4. **Where does inner TLS actually terminate?** (a) *Inside Envoy* (Envoy is the inner endpoint, co-resident with/in the TEE, plaintext to the workload) — then WASM can see the attestation HTTP exchange in cleartext, and families A/C apply directly. (b) *Inside the TEE workload* (Envoy only forwards inner-encrypted bytes) — then the WASM filter can't see the inner cleartext and the design must change (push toward B / in-workload attestation). **This single fact gates A/C vs B — confirm.**  
5. **What does the SDK's signed bundle cover** (does it bind the live exporter)? — see §3 token analysis.

---

## 6\. Proposed next experiment (ready to build)

A minimal proof on the *exact* target Envoy version:

- \~40-line WASM filter (Rust **or** C++ proxy-wasm SDK): L4 writes a Connection-lifespan marker via `declare_property` \+ set; L7 logs the per-stream read.  
- Minimal two-listener Envoy config: public listener \+ internal listener with loopback (`internal_upstream_transport`).  
- Drive multiple HTTP/2 streams over one connection, then a fresh connection.  
- **Expected:** one attestation amortizes across many streams on the same connection; a fresh connection reads "absent" until it attests. This directly demonstrates the A1 mechanism and closes OPEN items \#1 and \#2.

(Decision needed before building: Rust vs C++ SDK; and OPEN item \#4, since it determines whether the filter can see inner cleartext at all.)

---

## 7\. Key reference links

**The SDK**

- Google prompt-encryption SDK: [https://github.com/google/prompt-encryption-sdk](https://github.com/google/prompt-encryption-sdk)

**Envoy docs**

- Internal listener (loopback): [https://www.envoyproxy.io/docs/envoy/latest/configuration/other\_features/internal\_listener](https://www.envoyproxy.io/docs/envoy/latest/configuration/other_features/internal_listener)  
- Sharing data between filters (filter-state lifespans; shared-with-upstream; internal\_upstream\_transport copy behavior; hashable shared objects → separate upstream connection): [https://www.envoyproxy.io/docs/envoy/latest/intro/arch\_overview/advanced/data\_sharing\_between\_filters](https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/advanced/data_sharing_between_filters)  
- WASM network filter: [https://www.envoyproxy.io/docs/envoy/latest/configuration/listeners/network\_filters/wasm\_filter](https://www.envoyproxy.io/docs/envoy/latest/configuration/listeners/network_filters/wasm_filter)  
- WASM HTTP filter: [https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http\_filters/wasm\_filter](https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/wasm_filter)  
- WASM proto (vm\_id sharing, fail-open/closed, root\_id): [https://www.envoyproxy.io/docs/envoy/latest/api-v3/extensions/wasm/v3/wasm.proto](https://www.envoyproxy.io/docs/envoy/latest/api-v3/extensions/wasm/v3/wasm.proto)

**Envoy source (the evidence in §4)** — replace `main` with your pinned tag to check version skew

- foreign functions (declare\_property / set\_envoy\_filter\_state): [https://raw.githubusercontent.com/envoyproxy/envoy/main/source/extensions/common/wasm/foreign.cc](https://raw.githubusercontent.com/envoyproxy/envoy/main/source/extensions/common/wasm/foreign.cc)  
- lifespan enum proto: [https://raw.githubusercontent.com/envoyproxy/envoy/main/source/extensions/common/wasm/ext/declare\_property.proto](https://raw.githubusercontent.com/envoyproxy/envoy/main/source/extensions/common/wasm/ext/declare_property.proto)  
- WASM context (setProperty default lifespan; read path connection→stream): [https://raw.githubusercontent.com/envoyproxy/envoy/main/source/extensions/common/wasm/context.cc](https://raw.githubusercontent.com/envoyproxy/envoy/main/source/extensions/common/wasm/context.cc)  
- CI proof (DownstreamConnection declare/set/get round trip): [https://raw.githubusercontent.com/envoyproxy/envoy/main/test/extensions/filters/http/wasm/test\_data/test\_cpp.cc](https://raw.githubusercontent.com/envoyproxy/envoy/main/test/extensions/filters/http/wasm/test_data/test_cpp.cc)  
- historical context (connection filter-state lookup for HTTP): [https://github.com/envoyproxy/envoy-wasm/issues/402](https://github.com/envoyproxy/envoy-wasm/issues/402)

**Proxy-Wasm SDKs**

- ABI spec: [https://github.com/proxy-wasm/spec](https://github.com/proxy-wasm/spec)  
- Rust SDK: [https://github.com/proxy-wasm/proxy-wasm-rust-sdk](https://github.com/proxy-wasm/proxy-wasm-rust-sdk)  
- C++ SDK: [https://github.com/proxy-wasm/proxy-wasm-cpp-sdk](https://github.com/proxy-wasm/proxy-wasm-cpp-sdk)

**Token-binding RFCs (for the header-token / exporter-binding analysis)**

- RFC 9449 (DPoP — proof-of-possession at the application layer): [https://www.rfc-editor.org/rfc/rfc9449](https://www.rfc-editor.org/rfc/rfc9449)  
- RFC 8705 (OAuth 2.0 mutual-TLS / certificate-bound access tokens): [https://www.rfc-editor.org/rfc/rfc8705](https://www.rfc-editor.org/rfc/rfc8705)  
- RFC 5705 (TLS keying-material exporters): [https://www.rfc-editor.org/rfc/rfc5705](https://www.rfc-editor.org/rfc/rfc5705)

---

## 8\. One-paragraph summary for a fresh agent

We're wrapping Google's prompt-encryption SDK in Envoy with nested TLS: outer TLS is untrusted hop-by-hop transport terminating on the public listener; inner TLS is the end-to-end, attested channel that terminates on an internal (loopback) listener where a WASM filter performs attestation. The problem: attestation is a per-connection fact (bound to the inner TLS exporter) but Envoy processes HTTP/2 streams individually, so a stream-scope filter can't tell whether its connection was attested — and a global flag is wrong because new/unattested connections appear constantly. We verified from Envoy source \+ CI that the cleanest fix (A1: write a **Connection-lifespan** filter-state marker at L4 via the `declare_property` foreign function, read it per-stream at L7) is **config-only WASM, no Envoy fork**. A2 (a lock-free per-worker VM-local map keyed by connection id) is the portable fallback. Outstanding decisions: where inner TLS actually terminates (gates whether the filter can see inner cleartext at all), whether the inner exporter is readable from WASM, and whether the SDK's signed bundle binds the live exporter (which would make a per-request connection-bound token viable and the stream-scope problem disappear). Next step is a minimal loopback \+ WASM experiment on the exact target Envoy version.  
