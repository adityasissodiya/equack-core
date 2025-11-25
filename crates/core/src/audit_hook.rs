// crates/core/src/audit_hook.rs
#![cfg(feature = "audit")]

use crate::audit::AuditEvent;

/// Minimal interface core/replay can call to record audit events
/// without depending on storage details.
pub trait AuditHook {
    fn on_event(&mut self, ev: AuditEvent);
}

/// Default no-op hook to keep existing call sites simple.
pub struct NoopAuditHook;
impl AuditHook for NoopAuditHook {
    fn on_event(&mut self, _ev: AuditEvent) {}
}
