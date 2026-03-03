//! Core CRDT module for ECAC M2.
//!
//! We implement two minimal CRDTs with happens-before (HB) semantics derived
//! from the M1 DAG:
//!   - MVReg (multi-value register): concurrent winners are kept; HB-overwritten
//!     values are removed. Deterministic projection uses min(blake3(value)).
//!   - ORSet (observed-remove set): adds are tagged by op_id, removals only kill
//!     HB-visible add-tags. Deterministic iteration by elem_key, and projection
//!     for an element uses min(blake3(value)) across its active tags.

pub mod mvreg;
pub mod orset;

pub use mvreg::MVReg;
pub use orset::{ORSet, OrElem};
