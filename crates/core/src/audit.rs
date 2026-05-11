use once_cell::sync::OnceCell;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::crypto::PublicKeyBytes;
use crate::op::OpId;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AppliedReason {
    #[serde(rename = "authorized")]
    Authorized,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SkipReason {
    DenyWins,
    InvalidSig,
    BadParent,
    RevokedCred,
    ExpiredCred,
    OutOfScope,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuditEvent {
    IngestedOp {
        op_id: OpId,
        author_pk: PublicKeyBytes,
        parents: Vec<OpId>,
        verified_sig: bool,
    },
    AppliedOp {
        op_id: OpId,
        topo_idx: u64,
        reason: AppliedReason,
    },
    SkippedOp {
        op_id: OpId,
        topo_idx: u64,
        reason: SkipReason,
    },
    ViewEvent {
        viewer_node: [u8; 32],
        obj: String,
        field: String,
        projection_hash: [u8; 32],
    },
    Checkpoint {
        checkpoint_id: u64,
        topo_idx: u64,
        state_digest: [u8; 32],
    },
    SyncEvent {
        peer_id: [u8; 32],
        fetched: u32,
        duplicates: u32,
    },
}

pub trait AuditSink: Send + Sync {
    fn emit(&self, event: &AuditEvent) -> Result<(), String>;
}

static SINK: OnceCell<Arc<dyn AuditSink>> = OnceCell::new();

pub fn set_audit_sink(s: Arc<dyn AuditSink>) -> Result<(), ()> {
    SINK.set(s).map_err(|_| ())
}

pub fn emit(event: &AuditEvent) {
    if let Some(s) = SINK.get() {
        let _ = s.emit(event);
    }
}
