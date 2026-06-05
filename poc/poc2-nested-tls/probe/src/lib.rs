// POC 2 probe — runs on the INTERNAL listener (where inner TLS terminates).
// If it logs the cleartext HTTP request, then inner TLS terminated *inside Envoy*
// and a WASM filter can see the decrypted stream (resolves much of OPEN #4).
// It also dumps which TLS connection properties WASM can read — seeds POC 4 (EKM).

use log::info;
use proxy_wasm::traits::*;
use proxy_wasm::types::*;

proxy_wasm::main! {{
    proxy_wasm::set_log_level(LogLevel::Info);
    proxy_wasm::set_root_context(|_| -> Box<dyn RootContext> { Box::new(ProbeRoot) });
}}

struct ProbeRoot;
impl Context for ProbeRoot {}
impl RootContext for ProbeRoot {
    fn get_type(&self) -> Option<ContextType> {
        Some(ContextType::HttpContext)
    }
    fn create_http_context(&self, _id: u32) -> Option<Box<dyn HttpContext>> {
        Some(Box::new(Probe))
    }
}

struct Probe;
impl Context for Probe {}
impl HttpContext for Probe {
    fn on_http_request_headers(&mut self, _n: usize, _e: bool) -> Action {
        let scheme = self.get_http_request_header(":scheme").unwrap_or_default();
        let path = self.get_http_request_header(":path").unwrap_or_default();
        let proto = self.get_http_request_header(":method").unwrap_or_default();
        info!("[INNER-L7] cleartext HTTP seen: method={} scheme={} path={}", proto, scheme, path);

        // Which TLS properties does WASM get at stream scope? (POC 4 groundwork.)
        for prop in [
            "tls_version",
            "requested_server_name",
            "subject_local_certificate",
            "subject_peer_certificate",
            "mtls",
        ] {
            match self.get_property(vec!["connection", prop]) {
                Some(v) => info!("[INNER-L7] connection.{} = {:?}", prop, String::from_utf8_lossy(&v)),
                None => info!("[INNER-L7] connection.{} = <none>", prop),
            }
        }
        Action::Continue
    }
}
