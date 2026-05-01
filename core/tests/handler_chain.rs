//! Handler chain runner behavior tests.

use std::{cell::Cell, net::SocketAddr, time::Duration};

use mitm_core::{
    handler::{
        run_handler_chain, ClientEffect, Decision, DecisionError, DecisionKind, DropScope,
        DropSpec, Handler, HandlerContext, HandlerOutcome, HandlerPhase, HandlerResult,
        HttpResponseSpec, PatchOp, PatchSet, StreamSlot, UpstreamEffect,
    },
    intercept::{InterceptSpec, TimeoutAction},
    observability::AuditEvent,
    session::{IngressSource, ProcessingMode, Session, SessionId, TargetAddr, TlsPolicy},
};

fn test_session() -> Session {
    let client = SocketAddr::from(([127, 0, 0, 1], 50_100));
    let listener = SocketAddr::from(([127, 0, 0, 1], 1080));
    let target = TargetAddr::domain("example.com", 443).unwrap();
    let source = IngressSource::Socks5 { listener, client };

    Session::new(SessionId::new(42), client, target, source)
}

fn context(phase: HandlerPhase) -> HandlerContext {
    HandlerContext {
        phase,
        session: test_session(),
        stream: StreamSlot::Pending,
        pending_patches: PatchSet::default(),
        pause: None,
        drop_action: None,
        mock_response: None,
        audit_events: Vec::new(),
    }
}

struct FixedHandler {
    name: &'static str,
    outcome: HandlerOutcome,
    calls: Cell<usize>,
}

impl FixedHandler {
    fn new(name: &'static str, decision: Option<Decision>, control: HandlerResult) -> Self {
        Self {
            name,
            outcome: HandlerOutcome { decision, control },
            calls: Cell::new(0),
        }
    }

    fn calls(&self) -> usize {
        self.calls.get()
    }
}

impl Handler for FixedHandler {
    fn name(&self) -> &'static str {
        self.name
    }

    fn handle(&self, _ctx: &mut HandlerContext) -> HandlerOutcome {
        self.calls.set(self.calls.get() + 1);
        self.outcome.clone()
    }
}

struct PhaseAdvanceHandler {
    name: &'static str,
    next_phase: HandlerPhase,
    decision: Option<Decision>,
    calls: Cell<usize>,
}

impl PhaseAdvanceHandler {
    const fn new(name: &'static str, next_phase: HandlerPhase, decision: Option<Decision>) -> Self {
        Self {
            name,
            next_phase,
            decision,
            calls: Cell::new(0),
        }
    }

    fn calls(&self) -> usize {
        self.calls.get()
    }
}

impl Handler for PhaseAdvanceHandler {
    fn name(&self) -> &'static str {
        self.name
    }

    fn handle(&self, ctx: &mut HandlerContext) -> HandlerOutcome {
        self.calls.set(self.calls.get() + 1);
        ctx.phase = self.next_phase;
        HandlerOutcome {
            decision: self.decision.clone(),
            control: HandlerResult::Continue,
        }
    }
}

#[test]
fn set_raw_tunnel_switches_mode_and_stops_at_stop_handler() {
    let mut ctx = context(HandlerPhase::Connect);
    let set_raw = FixedHandler::new(
        "set-raw",
        Some(Decision::SetRawTunnel),
        HandlerResult::Continue,
    );
    let stop = FixedHandler::new("stop", None, HandlerResult::Stop);
    let after_stop = FixedHandler::new("after-stop", None, HandlerResult::Continue);

    run_handler_chain(&mut ctx, &[&set_raw, &stop, &after_stop]).unwrap();

    assert_eq!(ctx.session.mode(), ProcessingMode::RawTunnel);
    assert_eq!(set_raw.calls(), 1);
    assert_eq!(stop.calls(), 1);
    assert_eq!(after_stop.calls(), 0);
    assert!(matches!(
        ctx.audit_events.as_slice(),
        [AuditEvent::DecisionApplied { handler, .. }] if handler == "set-raw"
    ));
}

#[test]
fn set_tls_mitm_and_set_tls_bypass_are_only_legal_in_tls_phase() {
    let mut mitm_ctx = context(HandlerPhase::TlsClientHello);
    let mitm = FixedHandler::new("mitm", Some(Decision::SetTlsMitm), HandlerResult::Continue);

    run_handler_chain(&mut mitm_ctx, &[&mitm]).unwrap();

    assert_eq!(mitm_ctx.session.tls_policy(), TlsPolicy::Mitm);
    assert_eq!(mitm_ctx.audit_events.len(), 1);

    let mut bypass_ctx = context(HandlerPhase::TlsClientHello);
    let bypass = FixedHandler::new(
        "bypass",
        Some(Decision::SetTlsBypass),
        HandlerResult::Continue,
    );

    run_handler_chain(&mut bypass_ctx, &[&bypass]).unwrap();

    assert_eq!(bypass_ctx.session.tls_policy(), TlsPolicy::Bypass);
    assert_eq!(bypass_ctx.audit_events.len(), 1);

    let mut request_ctx = context(HandlerPhase::RequestBeforeIntercept);
    let illegal = FixedHandler::new(
        "illegal",
        Some(Decision::SetTlsMitm),
        HandlerResult::Continue,
    );

    assert_eq!(
        run_handler_chain(&mut request_ctx, &[&illegal]),
        Err(DecisionError::DecisionNotAllowed {
            phase: HandlerPhase::RequestBeforeIntercept,
            decision: DecisionKind::SetTlsMitm,
        })
    );
    assert_eq!(request_ctx.session.tls_policy(), TlsPolicy::Undecided);
}

#[test]
fn illegal_decision_is_rejected_and_audit_event_is_recorded() {
    let mut ctx = context(HandlerPhase::ResponseBeforeIntercept);
    let illegal = FixedHandler::new(
        "mock-response",
        Some(Decision::MockResponse(HttpResponseSpec {
            status: 200,
            headers: Vec::new(),
            body: b"mock".to_vec(),
        })),
        HandlerResult::Continue,
    );

    let result = run_handler_chain(&mut ctx, &[&illegal]);

    assert_eq!(
        result,
        Err(DecisionError::DecisionNotAllowed {
            phase: HandlerPhase::ResponseBeforeIntercept,
            decision: DecisionKind::MockResponse,
        })
    );
    assert!(matches!(
        ctx.audit_events.as_slice(),
        [AuditEvent::DecisionRejected {
            phase: HandlerPhase::ResponseBeforeIntercept,
            handler,
            ..
        }] if handler == "mock-response"
    ));
}

#[test]
fn chain_runner_applies_pause_patch_drop_and_mock_response_actions() {
    let mut request_ctx = context(HandlerPhase::RequestBeforeIntercept);
    let pause = InterceptSpec {
        phase: HandlerPhase::RequestBeforeIntercept,
        timeout: Duration::from_secs(10),
        timeout_action: TimeoutAction::FailOpen,
    };
    let pause_handler = FixedHandler::new(
        "pause",
        Some(Decision::Pause(pause.clone())),
        HandlerResult::Continue,
    );
    let patch_handler = FixedHandler::new(
        "patch",
        Some(Decision::Patch(PatchSet::new(vec![PatchOp::SetHeader {
            name: "x-stage".to_owned(),
            value: "task3".to_owned(),
        }]))),
        HandlerResult::Continue,
    );
    let mock = HttpResponseSpec {
        status: 204,
        headers: Vec::new(),
        body: Vec::new(),
    };
    let mock_handler = FixedHandler::new(
        "mock",
        Some(Decision::MockResponse(mock.clone())),
        HandlerResult::Continue,
    );
    let after_mock = FixedHandler::new("after-mock", None, HandlerResult::Continue);

    run_handler_chain(
        &mut request_ctx,
        &[&patch_handler, &mock_handler, &after_mock],
    )
    .unwrap();

    assert_eq!(request_ctx.pending_patches.ops.len(), 1);
    assert_eq!(request_ctx.mock_response, Some(mock));
    assert_eq!(after_mock.calls(), 0);
    assert_eq!(request_ctx.audit_events.len(), 2);

    let mut paused_ctx = context(HandlerPhase::RequestBeforeIntercept);
    let after_pause = FixedHandler::new("after-pause", None, HandlerResult::Continue);

    run_handler_chain(&mut paused_ctx, &[&pause_handler, &after_pause]).unwrap();

    assert_eq!(paused_ctx.pause, Some(pause));
    assert_eq!(after_pause.calls(), 0);
    assert_eq!(paused_ctx.audit_events.len(), 1);

    let mut response_ctx = context(HandlerPhase::ResponseBeforeIntercept);
    let drop = DropSpec {
        scope: DropScope::Transaction,
        client_effect: ClientEffect::Close,
        upstream_effect: UpstreamEffect::Close,
        reason: "blocked".to_owned(),
    };
    let drop_handler = FixedHandler::new(
        "drop",
        Some(Decision::Drop(drop.clone())),
        HandlerResult::Continue,
    );
    let after_drop = FixedHandler::new("after-drop", None, HandlerResult::Continue);

    run_handler_chain(&mut response_ctx, &[&drop_handler, &after_drop]).unwrap();

    assert_eq!(response_ctx.drop_action, Some(drop));
    assert_eq!(after_drop.calls(), 0);
    assert_eq!(response_ctx.audit_events.len(), 1);
}

#[test]
fn chain_runner_validates_decision_against_phase_after_each_handler_runs() {
    let mut ctx = context(HandlerPhase::Connect);
    let advance = PhaseAdvanceHandler::new("phase-advance", HandlerPhase::TlsClientHello, None);
    let tls_policy = FixedHandler::new(
        "tls-policy",
        Some(Decision::SetTlsMitm),
        HandlerResult::Continue,
    );

    run_handler_chain(&mut ctx, &[&advance, &tls_policy]).unwrap();

    assert_eq!(advance.calls(), 1);
    assert_eq!(ctx.phase, HandlerPhase::TlsClientHello);
    assert_eq!(ctx.session.tls_policy(), TlsPolicy::Mitm);
    assert!(matches!(
        ctx.audit_events.as_slice(),
        [AuditEvent::DecisionApplied {
            phase: HandlerPhase::TlsClientHello,
            handler,
            ..
        }] if handler == "tls-policy"
    ));
}

#[test]
fn same_handler_decision_is_validated_against_phase_before_handler_runs() {
    let mut ctx = context(HandlerPhase::Connect);
    let mock = HttpResponseSpec {
        status: 200,
        headers: Vec::new(),
        body: b"mock".to_vec(),
    };
    let illegal = PhaseAdvanceHandler::new(
        "connect-to-request-with-mock",
        HandlerPhase::RequestBeforeIntercept,
        Some(Decision::MockResponse(mock)),
    );

    let result = run_handler_chain(&mut ctx, &[&illegal]);

    assert_eq!(
        result,
        Err(DecisionError::DecisionNotAllowed {
            phase: HandlerPhase::Connect,
            decision: DecisionKind::MockResponse,
        })
    );
    assert_eq!(ctx.phase, HandlerPhase::RequestBeforeIntercept);
    assert!(matches!(
        ctx.audit_events.as_slice(),
        [AuditEvent::DecisionRejected {
            phase: HandlerPhase::Connect,
            handler,
            ..
        }] if handler == "connect-to-request-with-mock"
    ));
}
