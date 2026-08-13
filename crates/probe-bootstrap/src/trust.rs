//! Build-fixed Probe Distribution Trust Root material.
//!
//! The Bootstrap executable never accepts this trust root from its command
//! line, environment, Hub, or downloaded metadata. Production values are
//! generated only by `build.rs` behind the explicit `compiled-trust`
//! feature; test and development builds intentionally have no production root.

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum BootstrapRole {
    Acquirer,
    Activator,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct BuildTrust {
    pub distribution: &'static str,
    pub role: BootstrapRole,
    pub root_pem: &'static str,
    pub root_fingerprint: &'static str,
    pub root_key_id: &'static str,
    pub target: &'static str,
    pub version: &'static str,
}

impl BuildTrust {
    pub fn is_for(self, role: BootstrapRole) -> bool {
        self.role == role
    }
}

include!(concat!(env!("OUT_DIR"), "/build_trust.rs"));

pub fn embedded_production_trust() -> Option<BuildTrust> {
    GENERATED_PRODUCTION_TRUST
}

/// Returns trust only when the compiled binary's role agrees with the caller.
/// A copied or relabelled binary therefore fails before accepting any remote
/// metadata, archive bytes, or activation input.
pub fn embedded_production_trust_for(role: BootstrapRole) -> Option<BuildTrust> {
    embedded_production_trust().filter(|trust| trust.is_for(role))
}

/// Self-describing, length-prefixed bytes kept in a dedicated ELF section for
/// release inspection. It contains a value only in an explicit compiled-trust
/// build, never in a default or test build.
#[used]
#[unsafe(no_mangle)]
#[unsafe(link_section = ".enoki_bootstrap")]
pub static EMBEDDED_BUILD_IDENTITY: [u8; GENERATED_BUILD_IDENTITY_BYTES.len()] =
    GENERATED_BUILD_IDENTITY_BYTES;

/// A link-retention boundary only: it exposes no mutable trust state and is
/// never used for runtime configuration. `build.rs` makes the final binary
/// retain this function, which in turn retains the inspectable identity bytes.
#[unsafe(no_mangle)]
pub extern "C" fn enoki_bootstrap_build_identity() -> *const u8 {
    EMBEDDED_BUILD_IDENTITY.as_ptr()
}

#[cfg(test)]
mod tests {
    use super::{BootstrapRole, BuildTrust, embedded_production_trust};

    #[test]
    fn default_build_has_no_production_distribution_trust_root() {
        assert!(embedded_production_trust().is_none());
    }

    #[test]
    fn build_trust_refuses_the_other_bootstrap_role() {
        let acquirer = BuildTrust {
            distribution: "enoki",
            role: BootstrapRole::Acquirer,
            root_pem: "",
            root_fingerprint: "",
            root_key_id: "",
            target: "x86_64-unknown-linux-gnu",
            version: "v1.2.3",
        };
        assert!(acquirer.is_for(BootstrapRole::Acquirer));
        assert!(!acquirer.is_for(BootstrapRole::Activator));
    }
}
