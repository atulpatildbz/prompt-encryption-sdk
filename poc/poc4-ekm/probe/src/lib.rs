// POC 4 — what TLS material can a WASM filter read at stream scope on the inner listener?
// Specifically: is the RFC 5705 keying-material exporter (the SDK's attestation binding)
// reachable from WASM? Runs on the nested-TLS inner listener (inner TLS = TLSv1.3).
// We enumerate the standard connection attributes AND probe exporter/EKM-style names.

use log::info;
use proxy_wasm::traits::*;
use proxy_wasm::types::*;

// Standard Envoy "connection" attributes (documented set).
const STD: &[&str] = &[
    "id",
    "mtls",
    "requested_server_name",
    "tls_version",
    "subject_local_certificate",
    "subject_peer_certificate",
    "dns_san_local_certificate",
    "dns_san_peer_certificate",
    "uri_san_local_certificate",
    "uri_san_peer_certificate",
    "sha256_peer_certificate_digest",
    "ja3_fingerprint",
    "ja4_fingerprint",
    "termination_details",
];

// Names a custom RFC 5705 exporter MIGHT be exposed under (we expect all <none>).
const EXPORTER_GUESSES: &[&str] = &[
    "ekm",
    "exported_keying_material",
    "keying_material",
    "tls_exporter",
    "exporter",
    "tls_keying_material",
];

proxy_wasm::main! {{
    proxy_wasm::set_log_level(LogLevel::Info);
    proxy_wasm::set_root_context(|_| -> Box<dyn RootContext> { Box::new(R) });
}}

struct R;
impl Context for R {}
impl RootContext for R {
    fn get_type(&self) -> Option<ContextType> { Some(ContextType::HttpContext) }
    fn create_http_context(&self, _id: u32) -> Option<Box<dyn HttpContext>> { Some(Box::new(P)) }
}

struct P;
impl Context for P {}
impl HttpContext for P {
    fn on_http_request_headers(&mut self, _n: usize, _e: bool) -> Action {
        info!("[EKM-PROBE] === standard connection attributes ===");
        for k in STD {
            match self.get_property(vec!["connection", k]) {
                Some(v) => info!("[EKM-PROBE] connection.{} = {:?}", k, String::from_utf8_lossy(&v)),
                None => info!("[EKM-PROBE] connection.{} = <none>", k),
            }
        }
        info!("[EKM-PROBE] === exporter / EKM name guesses (expect all <none>) ===");
        for k in EXPORTER_GUESSES {
            let a = self.get_property(vec!["connection", k]).is_some();
            let b = self.get_property(vec![k]).is_some();
            info!("[EKM-PROBE] connection.{k} present={a} | bare {k} present={b}");
        }
        Action::Continue
    }
}
