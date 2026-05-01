//! Metrics, tracing, debug events, and audit records.

use crate::handler::HandlerPhase;

/// Minimal audit event emitted around decision validation and application.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditEvent {
    /// A handler decision was accepted and applied.
    DecisionApplied {
        /// Phase where the decision was emitted.
        phase: HandlerPhase,
        /// Handler name or source identifier.
        handler: String,
        /// Human-readable decision summary.
        summary: String,
    },
    /// A handler decision was rejected by validation.
    DecisionRejected {
        /// Phase where the decision was emitted.
        phase: HandlerPhase,
        /// Handler name or source identifier.
        handler: String,
        /// Human-readable decision summary.
        summary: String,
        /// Structured rejection reason rendered for audit storage.
        reason: String,
    },
}
