// POC 3 — attestation gate, PURE L7, using the A2 mechanism (VM-local map).
//
// Why A2 and not A1 here: a verdict born at L7 cannot be written into A1's
// connection-lifespan FILTER STATE — set_property from L7 lands in stream scope, and
// set_envoy_filter_state(NotFound) won't take an arbitrary WASM name (observed: POC 3
// runs #1/#2). A1's connection-state WRITE only works from L4. So for an L7-born verdict
// we use A2: a VM-local map keyed by connection id. A connection is pinned to one worker
// = one single-threaded WASM VM, so the map needs no lock.
//
//   * on /_attest: (mocked) attestation OK -> insert connection_id into the attested set.
//   * on any other path: allow iff connection_id is in the set, else 403.

use std::cell::RefCell;
use std::collections::HashSet;

use log::info;
use proxy_wasm::traits::*;
use proxy_wasm::types::*;

thread_local! {
    // VM-local (single worker thread) set of attested connection ids. No lock needed.
    static ATTESTED: RefCell<HashSet<u64>> = RefCell::new(HashSet::new());
}

proxy_wasm::main! {{
    proxy_wasm::set_log_level(LogLevel::Info);
    proxy_wasm::set_root_context(|_| -> Box<dyn RootContext> { Box::new(GateRoot) });
}}

struct GateRoot;
impl Context for GateRoot {}
impl RootContext for GateRoot {
    fn get_type(&self) -> Option<ContextType> {
        Some(ContextType::HttpContext)
    }
    fn create_http_context(&self, _id: u32) -> Option<Box<dyn HttpContext>> {
        Some(Box::new(Gate))
    }
}

struct Gate;
impl Context for Gate {}
impl HttpContext for Gate {
    fn on_http_request_headers(&mut self, _n: usize, _e: bool) -> Action {
        let path = self.get_http_request_header(":path").unwrap_or_default();
        let conn_id = self.connection_id();

        if path == "/_attest" {
            // --- MOCKED attestation: pretend GCA evidence + EKM binding verified OK. ---
            ATTESTED.with(|s| s.borrow_mut().insert(conn_id));
            info!("[GATE] /_attest -> conn_id={} marked attested (A2 VM-local map)", conn_id);
            self.send_http_response(200, vec![("x-poc", "attested")], Some(b"attested\n"));
            return Action::Pause;
        }

        let ok = ATTESTED.with(|s| s.borrow().contains(&conn_id));
        if ok {
            info!("[GATE] ALLOW path={} conn_id={} (attested)", path, conn_id);
            Action::Continue
        } else {
            info!("[GATE] REJECT path={} conn_id={} (not attested)", path, conn_id);
            self.send_http_response(403, vec![("x-poc", "unattested")], Some(b"unattested\n"));
            Action::Pause
        }
    }
}

impl Gate {
    // Envoy exposes the connection id as a little-endian u64 in the "connection_id" property.
    fn connection_id(&self) -> u64 {
        match self.get_property(vec!["connection_id"]) {
            Some(b) if b.len() >= 8 => {
                let mut a = [0u8; 8];
                a.copy_from_slice(&b[..8]);
                u64::from_le_bytes(a)
            }
            _ => 0,
        }
    }
}
