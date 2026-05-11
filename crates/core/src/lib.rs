pub mod crdt;
pub mod crypto;
pub mod dag;
pub mod hlc;
pub mod op;
pub mod replay;
pub mod serialize;
pub mod state;

// M4 additions
pub mod policy;
pub mod status;
pub mod trust;
pub mod vc; // keep after vc/trust/status so it can use them
pub mod trustview;

pub mod metrics; // M7 metrics registry

// M8 (feature-gated)
#[cfg(feature = "audit")]
pub mod audit;
pub mod audit_hook;
