//! Protocol processing core for the MITM traffic debugging toolkit.
//!
//! The crate is intentionally limited to the Rust core. Platform access,
//! certificate installation, UI, and system proxy integration live outside
//! this package.

/// TCP byte classification and protocol hints.
pub mod classify;
/// Runtime configuration models.
pub mod config;
/// Linear handler-chain contracts and decision validation.
pub mod handler;
/// HTTP parsing, serialization, and body state management.
pub mod http;
/// Manual intercept tickets and resume decisions.
pub mod intercept;
/// Metrics, tracing, and audit events.
pub mod observability;
/// Lua hook registry and sandbox integration.
pub mod scripting;
/// Session, transaction, and flow identity types.
pub mod session;
/// SOCKS5 ingress handling.
pub mod socks5;
/// Flow metadata and body spool storage.
pub mod storage;
/// Tag sets and state-derived tag rules.
pub mod tags;
/// TLS MITM, certificate, and bypass handling.
pub mod tls;
/// Upstream TCP and TLS connection management.
pub mod upstream;

/// Returns the package name used by the Rust core crate.
#[must_use]
pub const fn crate_name() -> &'static str {
    "mitm-core"
}
