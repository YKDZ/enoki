//! The Probe Bootstrap trust boundary.  This crate intentionally contains no
//! dependency on `enoki-probe`; acquisition and root activation meet only at a
//! small, deterministic stdin protocol.

#[cfg(feature = "acquirer")]
pub mod acquisition;
#[cfg(feature = "activator")]
pub mod activation;
mod bundle_role;
pub mod generation;
pub mod handoff;
#[cfg(feature = "activator")]
pub mod install;
pub mod lifecycle;
pub mod operation_status;
pub mod replacement;
pub mod secure_file;
pub mod trust;
pub mod verifier;
