//! Linear handler-chain contracts and decision validation primitives.

#![allow(clippy::module_name_repetitions)]

use std::{error::Error, fmt};

use crate::{
    intercept::InterceptSpec,
    observability::AuditEvent,
    session::{ApplicationProtocol, ProcessingMode, Session, TargetAddr, TlsPolicy},
};

/// Handler execution phase used by decision validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HandlerPhase {
    /// SOCKS5 CONNECT has been parsed and connection-level policy is evaluated.
    Connect,
    /// TLS `ClientHello` has been parsed and TLS policy is evaluated.
    TlsClientHello,
    /// HTTP request handling before manual interception.
    RequestBeforeIntercept,
    /// HTTP request handling after manual interception.
    RequestAfterIntercept,
    /// HTTP response handling before manual interception.
    ResponseBeforeIntercept,
    /// HTTP response handling after manual interception.
    ResponseAfterIntercept,
}

impl HandlerPhase {
    const fn allows_pause(self) -> bool {
        matches!(
            self,
            Self::Connect
                | Self::TlsClientHello
                | Self::RequestBeforeIntercept
                | Self::ResponseBeforeIntercept
        )
    }

    const fn is_request(self) -> bool {
        matches!(
            self,
            Self::RequestBeforeIntercept | Self::RequestAfterIntercept
        )
    }

    const fn is_response(self) -> bool {
        matches!(
            self,
            Self::ResponseBeforeIntercept | Self::ResponseAfterIntercept
        )
    }
}

impl fmt::Display for HandlerPhase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let phase = match self {
            Self::Connect => "connect",
            Self::TlsClientHello => "tls_client_hello",
            Self::RequestBeforeIntercept => "request_before_intercept",
            Self::RequestAfterIntercept => "request_after_intercept",
            Self::ResponseBeforeIntercept => "response_before_intercept",
            Self::ResponseAfterIntercept => "response_after_intercept",
        };
        f.write_str(phase)
    }
}

/// Chain control result returned by a handler.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HandlerResult {
    /// Continue executing the current chain.
    Continue,
    /// Stop executing the current chain.
    Stop,
}

/// Structured handler return value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandlerOutcome {
    /// Optional business decision to validate and apply.
    pub decision: Option<Decision>,
    /// Chain execution control result.
    pub control: HandlerResult,
}

/// Current stream ownership marker used by handler tests and chain state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamSlot {
    /// Stream has not been attached yet.
    Pending,
    /// Raw downstream stream is available.
    Raw,
    /// Prefix bytes were read and need replay.
    Peeked {
        /// Buffered prefix bytes.
        prefix: Vec<u8>,
    },
    /// TLS `ClientHello` bytes were parsed and need replay.
    TlsClientHelloParsed {
        /// Raw `ClientHello` bytes.
        raw_client_hello: Vec<u8>,
    },
    /// Stream is decrypted and associated with an application protocol.
    Decrypted {
        /// Negotiated or detected application protocol.
        app_protocol: ApplicationProtocol,
    },
    /// Stream is closed.
    Closed,
}

/// Mutable context shared by a linear handler chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandlerContext {
    /// Phase currently executed by this chain.
    pub phase: HandlerPhase,
    /// Session state owned by the chain.
    pub session: Session,
    /// Stream ownership marker.
    pub stream: StreamSlot,
    /// Pending patches accumulated in handler order.
    pub pending_patches: PatchSet,
    /// Pending intercept pause specification.
    pub pause: Option<InterceptSpec>,
    /// Pending drop action.
    pub drop_action: Option<DropSpec>,
    /// Pending mock response.
    pub mock_response: Option<HttpResponseSpec>,
    /// Audit events emitted while decisions are applied or rejected.
    pub audit_events: Vec<AuditEvent>,
}

/// Handler executed by [`run_handler_chain`].
pub trait Handler {
    /// Returns a stable handler name for audit events.
    fn name(&self) -> &'static str;

    /// Executes the handler against the mutable context.
    fn handle(&self, ctx: &mut HandlerContext) -> HandlerOutcome;
}

/// Business action emitted by handler, Lua hook, or control-plane resume logic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// Continue without business changes.
    Pass,
    /// Append one or more structured message or target patches.
    Patch(PatchSet),
    /// Pause processing and create an intercept ticket.
    Pause(InterceptSpec),
    /// Drop the current connection, transaction, or direction.
    Drop(DropSpec),
    /// Construct a local HTTP response and skip upstream request sending.
    MockResponse(HttpResponseSpec),
    /// Switch the session to raw TCP tunneling.
    SetRawTunnel,
    /// Select TLS MITM policy.
    SetTlsMitm,
    /// Select TLS bypass policy.
    SetTlsBypass,
}

impl Decision {
    const fn kind(&self) -> DecisionKind {
        match self {
            Self::Pass => DecisionKind::Pass,
            Self::Patch(_) => DecisionKind::Patch,
            Self::Pause(_) => DecisionKind::Pause,
            Self::Drop(_) => DecisionKind::Drop,
            Self::MockResponse(_) => DecisionKind::MockResponse,
            Self::SetRawTunnel => DecisionKind::SetRawTunnel,
            Self::SetTlsMitm => DecisionKind::SetTlsMitm,
            Self::SetTlsBypass => DecisionKind::SetTlsBypass,
        }
    }
}

/// Decision variant name used in structured validation errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DecisionKind {
    /// [`Decision::Pass`].
    Pass,
    /// [`Decision::Patch`].
    Patch,
    /// [`Decision::Pause`].
    Pause,
    /// [`Decision::Drop`].
    Drop,
    /// [`Decision::MockResponse`].
    MockResponse,
    /// [`Decision::SetRawTunnel`].
    SetRawTunnel,
    /// [`Decision::SetTlsMitm`].
    SetTlsMitm,
    /// [`Decision::SetTlsBypass`].
    SetTlsBypass,
}

impl fmt::Display for DecisionKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = match self {
            Self::Pass => "Pass",
            Self::Patch => "Patch",
            Self::Pause => "Pause",
            Self::Drop => "Drop",
            Self::MockResponse => "MockResponse",
            Self::SetRawTunnel => "SetRawTunnel",
            Self::SetTlsMitm => "SetTlsMitm",
            Self::SetTlsBypass => "SetTlsBypass",
        };
        f.write_str(kind)
    }
}

/// Ordered collection of patch operations.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PatchSet {
    /// Patch operations in handler execution order.
    pub ops: Vec<PatchOp>,
}

impl PatchSet {
    /// Creates a patch set from ordered operations.
    #[must_use]
    pub const fn new(ops: Vec<PatchOp>) -> Self {
        Self { ops }
    }

    /// Returns patch operations in application order.
    pub fn iter(&self) -> impl Iterator<Item = &PatchOp> {
        self.ops.iter()
    }

    /// Returns whether the patch set has no operations.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.ops.is_empty()
    }
}

/// Structured patch operation emitted before validation and application.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PatchOp {
    /// Replace the current upstream target.
    RedirectTarget {
        /// Replacement upstream target.
        target: TargetAddr,
    },
    /// Replace the HTTP request method.
    SetMethod(String),
    /// Replace the HTTP request URI.
    SetUri(String),
    /// Replace the HTTP response status code.
    SetStatus(u16),
    /// Replace existing header values with a single value.
    SetHeader {
        /// Header field name.
        name: String,
        /// Header field value.
        value: String,
    },
    /// Append a header value while preserving existing values.
    AppendHeader {
        /// Header field name.
        name: String,
        /// Header field value.
        value: String,
    },
    /// Remove all values for a header field name.
    RemoveHeader {
        /// Header field name.
        name: String,
    },
    /// Replace an HTTP body with buffered bytes.
    ReplaceBody(Vec<u8>),
}

impl PatchOp {
    const fn kind(&self) -> PatchKind {
        match self {
            Self::RedirectTarget { .. } => PatchKind::RedirectTarget,
            Self::SetMethod(_) => PatchKind::SetMethod,
            Self::SetUri(_) => PatchKind::SetUri,
            Self::SetStatus(_) => PatchKind::SetStatus,
            Self::SetHeader { .. } => PatchKind::SetHeader,
            Self::AppendHeader { .. } => PatchKind::AppendHeader,
            Self::RemoveHeader { .. } => PatchKind::RemoveHeader,
            Self::ReplaceBody(_) => PatchKind::ReplaceBody,
        }
    }
}

/// Patch variant name used in structured validation errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PatchKind {
    /// [`PatchOp::RedirectTarget`].
    RedirectTarget,
    /// [`PatchOp::SetMethod`].
    SetMethod,
    /// [`PatchOp::SetUri`].
    SetUri,
    /// [`PatchOp::SetStatus`].
    SetStatus,
    /// [`PatchOp::SetHeader`].
    SetHeader,
    /// [`PatchOp::AppendHeader`].
    AppendHeader,
    /// [`PatchOp::RemoveHeader`].
    RemoveHeader,
    /// [`PatchOp::ReplaceBody`].
    ReplaceBody,
}

impl fmt::Display for PatchKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = match self {
            Self::RedirectTarget => "RedirectTarget",
            Self::SetMethod => "SetMethod",
            Self::SetUri => "SetUri",
            Self::SetStatus => "SetStatus",
            Self::SetHeader => "SetHeader",
            Self::AppendHeader => "AppendHeader",
            Self::RemoveHeader => "RemoveHeader",
            Self::ReplaceBody => "ReplaceBody",
        };
        f.write_str(kind)
    }
}

/// Local HTTP response specification used by mock responses and fail responses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpResponseSpec {
    /// HTTP status code.
    pub status: u16,
    /// Ordered response headers.
    pub headers: Vec<(String, String)>,
    /// Response body bytes.
    pub body: Vec<u8>,
}

/// Drop behavior selected by policy or control-plane input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DropSpec {
    /// Drop target scope.
    pub scope: DropScope,
    /// Effect visible to the downstream client.
    pub client_effect: ClientEffect,
    /// Effect applied to the upstream side.
    pub upstream_effect: UpstreamEffect,
    /// Human-readable policy or protocol reason.
    pub reason: String,
}

/// Scope affected by a drop decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DropScope {
    /// Drop during connection setup.
    Connect,
    /// Drop the current HTTP transaction.
    Transaction,
    /// Drop the entire session.
    Session,
}

/// Downstream effect of a drop decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientEffect {
    /// Close the downstream connection.
    Close,
    /// Send a local HTTP response.
    LocalResponse(HttpResponseSpec),
    /// Close without sending protocol-level error bytes.
    SilentClose,
}

/// Upstream effect of a drop decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UpstreamEffect {
    /// Upstream has not been connected.
    NotConnected,
    /// Close the upstream connection.
    Close,
    /// Keep upstream reusable after the current transaction.
    Reusable,
}

/// Structured decision validation failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecisionError {
    /// Decision variant is not allowed in the handler phase.
    DecisionNotAllowed {
        /// Handler phase where validation failed.
        phase: HandlerPhase,
        /// Decision variant that was rejected.
        decision: DecisionKind,
    },
    /// Patch operation is not allowed in the handler phase.
    PatchNotAllowed {
        /// Handler phase where validation failed.
        phase: HandlerPhase,
        /// Patch variant that was rejected.
        patch: PatchKind,
    },
    /// Pause decision contains an intercept spec for a different phase.
    PausePhaseMismatch {
        /// Handler phase currently being validated.
        phase: HandlerPhase,
        /// Phase carried by the intercept spec.
        intercept_phase: HandlerPhase,
    },
}

impl fmt::Display for DecisionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DecisionNotAllowed { phase, decision } => {
                write!(f, "decision {decision} is not allowed in phase {phase}")
            }
            Self::PatchNotAllowed { phase, patch } => {
                write!(f, "patch {patch} is not allowed in phase {phase}")
            }
            Self::PausePhaseMismatch {
                phase,
                intercept_phase,
            } => write!(
                f,
                "pause spec phase {intercept_phase} does not match handler phase {phase}"
            ),
        }
    }
}

impl Error for DecisionError {}

/// Validates whether a decision is allowed in a handler phase.
///
/// This function only checks the stage-level decision matrix. Context-sensitive
/// constraints, including full [`DropSpec`] semantics and body-state rules for
/// [`PatchOp::ReplaceBody`], are left to later context validation or validation
/// handlers.
///
/// # Errors
///
/// Returns [`DecisionError`] when the decision variant is not allowed, when a
/// nested patch is not valid for the phase, or when a pause carries a mismatched
/// intercept phase.
pub fn validate_decision_for_phase(
    phase: HandlerPhase,
    decision: &Decision,
) -> Result<(), DecisionError> {
    match decision {
        Decision::Pass if phase != HandlerPhase::TlsClientHello => Ok(()),
        Decision::Patch(patches) if phase != HandlerPhase::TlsClientHello => {
            validate_patch_set_for_phase(phase, patches)
        }
        Decision::Pause(spec) => validate_pause_for_phase(phase, spec),
        Decision::Drop(_) => Ok(()),
        Decision::MockResponse(_) if phase.is_request() => Ok(()),
        Decision::SetRawTunnel if phase == HandlerPhase::Connect => Ok(()),
        Decision::SetTlsMitm | Decision::SetTlsBypass if phase == HandlerPhase::TlsClientHello => {
            Ok(())
        }
        _ => Err(DecisionError::DecisionNotAllowed {
            phase,
            decision: decision.kind(),
        }),
    }
}

/// Validates whether every patch operation is allowed in a handler phase.
///
/// This function only checks the stage-level patch matrix. It does not inspect
/// HTTP body ownership or buffering state; [`PatchOp::ReplaceBody`] body-state
/// limits are enforced by later context validation or validation handlers.
///
/// # Errors
///
/// Returns [`DecisionError::DecisionNotAllowed`] when the phase forbids
/// `Patch` entirely, such as `tls_client_hello`. Returns
/// [`DecisionError::PatchNotAllowed`] for the first operation that is outside
/// the patch matrix for the phase.
pub fn validate_patch_set_for_phase(
    phase: HandlerPhase,
    patches: &PatchSet,
) -> Result<(), DecisionError> {
    if phase == HandlerPhase::TlsClientHello {
        return Err(DecisionError::DecisionNotAllowed {
            phase,
            decision: DecisionKind::Patch,
        });
    }

    for patch in patches.iter() {
        if !is_patch_allowed_for_phase(phase, patch) {
            return Err(DecisionError::PatchNotAllowed {
                phase,
                patch: patch.kind(),
            });
        }
    }

    Ok(())
}

/// Runs a linear handler chain and applies each emitted decision immediately.
///
/// Decision validation uses the [`HandlerContext::phase`] captured before each
/// handler runs. A handler may advance `ctx.phase`, and that phase change is
/// visible to subsequent handlers, while the decision returned by the same
/// handler remains scoped to the phase in effect at handler entry.
///
/// # Errors
///
/// Returns [`DecisionError`] when a handler emits a decision that is invalid for
/// the current [`HandlerPhase`]. The rejection is recorded in
/// [`HandlerContext::audit_events`] before the error is returned.
pub fn run_handler_chain(
    ctx: &mut HandlerContext,
    handlers: &[&dyn Handler],
) -> Result<(), DecisionError> {
    for handler in handlers {
        let decision_phase = ctx.phase;
        let outcome = handler.handle(ctx);

        if let Some(decision) = outcome.decision {
            let summary = decision_summary(&decision);

            if let Err(error) = validate_decision_for_phase(decision_phase, &decision) {
                ctx.audit_events.push(AuditEvent::DecisionRejected {
                    phase: decision_phase,
                    handler: handler.name().to_owned(),
                    summary,
                    reason: error.to_string(),
                });
                return Err(error);
            }

            let should_stop = apply_decision(ctx, decision);
            ctx.audit_events.push(AuditEvent::DecisionApplied {
                phase: decision_phase,
                handler: handler.name().to_owned(),
                summary,
            });

            if should_stop {
                break;
            }
        }

        if outcome.control == HandlerResult::Stop {
            break;
        }
    }

    Ok(())
}

fn apply_decision(ctx: &mut HandlerContext, decision: Decision) -> bool {
    match decision {
        Decision::Pass => false,
        Decision::Patch(patches) => {
            ctx.pending_patches.ops.extend(patches.ops);
            false
        }
        Decision::Pause(spec) => {
            ctx.pause = Some(spec);
            true
        }
        Decision::Drop(spec) => {
            ctx.drop_action = Some(spec);
            true
        }
        Decision::MockResponse(response) => {
            ctx.mock_response = Some(response);
            true
        }
        Decision::SetRawTunnel => {
            ctx.session.set_mode(ProcessingMode::RawTunnel);
            false
        }
        Decision::SetTlsMitm => {
            ctx.session.set_tls_policy(TlsPolicy::Mitm);
            false
        }
        Decision::SetTlsBypass => {
            ctx.session.set_tls_policy(TlsPolicy::Bypass);
            false
        }
    }
}

fn decision_summary(decision: &Decision) -> String {
    decision.kind().to_string()
}

fn validate_pause_for_phase(
    phase: HandlerPhase,
    spec: &InterceptSpec,
) -> Result<(), DecisionError> {
    if !phase.allows_pause() {
        return Err(DecisionError::DecisionNotAllowed {
            phase,
            decision: DecisionKind::Pause,
        });
    }

    if spec.phase != phase {
        return Err(DecisionError::PausePhaseMismatch {
            phase,
            intercept_phase: spec.phase,
        });
    }

    Ok(())
}

fn is_patch_allowed_for_phase(phase: HandlerPhase, patch: &PatchOp) -> bool {
    match patch {
        PatchOp::RedirectTarget { .. } => phase == HandlerPhase::Connect || phase.is_request(),
        PatchOp::SetMethod(_) | PatchOp::SetUri(_) => phase.is_request(),
        PatchOp::SetStatus(_) => phase.is_response(),
        PatchOp::SetHeader { .. }
        | PatchOp::AppendHeader { .. }
        | PatchOp::RemoveHeader { .. }
        | PatchOp::ReplaceBody(_) => phase.is_request() || phase.is_response(),
    }
}
