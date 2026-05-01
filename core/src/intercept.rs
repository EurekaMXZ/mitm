//! Manual interception tickets, pause handling, and resume decisions.

use std::time::Duration;

use crate::handler::{Decision, DropSpec, HandlerPhase, HttpResponseSpec, PatchSet};

/// Action applied when an intercept ticket reaches its timeout.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TimeoutAction {
    /// Continue processing without applying manual changes.
    FailOpen,
    /// Close the relevant session or transaction.
    FailClose,
    /// Return a local HTTP response where protocol state allows it.
    FailResponse(HttpResponseSpec),
}

/// Specification for a manual interception pause.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterceptSpec {
    /// Handler phase that created the pause.
    pub phase: HandlerPhase,
    /// Maximum time to wait for a resume decision.
    pub timeout: Duration,
    /// Action applied when the timeout expires.
    pub timeout_action: TimeoutAction,
}

/// Control-plane decision used to resume a paused intercept ticket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResumeDecision {
    /// Resume without further changes.
    Resume,
    /// Apply patches and resume processing.
    PatchAndResume(PatchSet),
    /// Drop the relevant session or transaction.
    Drop(DropSpec),
    /// Use a local mock response and resume into response processing.
    MockResponse(HttpResponseSpec),
}

impl From<ResumeDecision> for Decision {
    fn from(value: ResumeDecision) -> Self {
        match value {
            ResumeDecision::Resume => Self::Pass,
            ResumeDecision::PatchAndResume(patches) => Self::Patch(patches),
            ResumeDecision::Drop(spec) => Self::Drop(spec),
            ResumeDecision::MockResponse(response) => Self::MockResponse(response),
        }
    }
}
