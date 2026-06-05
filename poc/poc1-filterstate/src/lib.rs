// POC 1 — Connection-lifespan filter-state round trip (the keystone).
//
// Proves the A1 mechanism on the target Envoy:
//   * an L4 network filter writes a marker at DownstreamConnection lifespan
//   * an L7 HTTP filter reads it back per stream
// One write should amortize across every stream on the same connection; a fresh
// connection (and the :10001 listener that has no write filter) should read ABSENT.
//
// ABI constants below are VERIFIED against Envoy `main`:
//   source/extensions/common/wasm/ext/declare_property.proto
//     WasmType:  Bytes=0, String=1, FlatBuffers=2, Protobuf=3
//     LifeSpan:  FilterChain=0, DownstreamRequest=1, DownstreamConnection=2
//     DeclarePropertyArguments: name=1(string) readonly=2(bool) type=3(WasmType)
//                               schema=4(bytes)  span=5(LifeSpan)

use log::{info, warn};
use proxy_wasm::traits::*;
use proxy_wasm::types::*;

const WASM_TYPE_BYTES: u8 = 0;
const LIFESPAN_DOWNSTREAM_CONNECTION: u8 = 2;

// Declared property name. No dot on purpose: path segments are matched verbatim,
// and the Envoy CI example uses a flat name ("structured_state").
const PROP: &str = "attested_state";
const MARKER: &[u8] = b"attested-marker-v1";

proxy_wasm::main! {{
    proxy_wasm::set_log_level(LogLevel::Info);
    proxy_wasm::set_root_context(|_| -> Box<dyn RootContext> {
        Box::new(AttestRoot { mode: Mode::Read })
    });
}}

enum Mode {
    Write, // L4 network filter
    Read,  // L7 HTTP filter
}

struct AttestRoot {
    mode: Mode,
}
impl Context for AttestRoot {}
impl RootContext for AttestRoot {
    fn on_configure(&mut self, _n: usize) -> bool {
        // The plugin `configuration` is a StringValue ("write"/"read"); its serialized
        // bytes end with the raw string, so match the suffix (avoids a protobuf dep).
        let cfg = self.get_plugin_configuration().unwrap_or_default();
        self.mode = if cfg.ends_with(b"write") { Mode::Write } else { Mode::Read };
        info!(
            "[root] mode={}",
            if matches!(self.mode, Mode::Write) { "WRITE(L4)" } else { "READ(L7)" }
        );
        true
    }
    // get_type MUST return a concrete type. Returning None makes the proxy-wasm
    // dispatcher hit unreachable!() on context creation (observed: POC1 run #1).
    fn get_type(&self) -> Option<ContextType> {
        Some(match self.mode {
            Mode::Write => ContextType::StreamContext,
            Mode::Read => ContextType::HttpContext,
        })
    }
    fn create_stream_context(&self, _id: u32) -> Option<Box<dyn StreamContext>> {
        Some(Box::new(WriteFilter))
    }
    fn create_http_context(&self, _id: u32) -> Option<Box<dyn HttpContext>> {
        Some(Box::new(ReadFilter))
    }
}

// ---------- L4: write the connection-lifespan marker once per connection ----------
struct WriteFilter;
impl Context for WriteFilter {}
impl StreamContext for WriteFilter {
    fn on_new_connection(&mut self) -> Action {
        // Step 1: declare the property at DownstreamConnection lifespan via the
        // declare_property foreign function (the convenience set_property API would
        // default to FilterChain lifespan, which would NOT survive across streams).
        let args = declare_args(PROP, WASM_TYPE_BYTES, LIFESPAN_DOWNSTREAM_CONNECTION);
        match self.call_foreign_function("declare_property", Some(&args)) {
            Ok(_) => info!("[L4] declared '{}' @ DownstreamConnection lifespan", PROP),
            Err(e) => warn!(
                "[L4] declare_property FAILED: {:?}  (OPEN#1: is the foreign fn present in this build?)",
                e
            ),
        }
        // Step 2: set the value.
        self.set_property(vec![PROP], Some(MARKER));
        info!("[L4] on_new_connection -> wrote '{}'", PROP);
        Action::Continue
    }
}

// ---------- L7: read the marker per stream ----------
struct ReadFilter;
impl Context for ReadFilter {}
impl HttpContext for ReadFilter {
    fn on_http_request_headers(&mut self, _num: usize, _eos: bool) -> Action {
        let path = self
            .get_http_request_header(":path")
            .unwrap_or_else(|| "<none>".into());
        match self.get_property(vec![PROP]) {
            Some(v) => info!("[L7] path={} -> attested={}", path, String::from_utf8_lossy(&v)),
            None => info!("[L7] path={} -> attested=ABSENT", path),
        }
        Action::Continue
    }
}

// Hand-encode DeclarePropertyArguments (proto3). proto3 omits default (0) values,
// so `type` is skipped when it is Bytes(0). Field numbers per the verified proto above.
fn declare_args(name: &str, wasm_type: u8, span: u8) -> Vec<u8> {
    let mut b = Vec::new();
    // field 1: name — wire type 2 (length-delimited). POC assumes name < 128 bytes.
    b.push((1 << 3) | 2);
    b.push(name.len() as u8);
    b.extend_from_slice(name.as_bytes());
    // field 3: type — wire type 0 (varint). Omit when default (Bytes=0).
    if wasm_type != 0 {
        b.push((3 << 3) | 0);
        b.push(wasm_type);
    }
    // field 5: span — wire type 0 (varint).
    b.push((5 << 3) | 0);
    b.push(span);
    b
}
