//! Handler chain runner behavior tests.

use std::{
    cell::Cell,
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    time::Duration,
};

use mitm_core::{
    classify::{ProtocolClassifierHandler, ReplayStream, H2C_PRIOR_KNOWLEDGE},
    handler::{
        run_handler_chain, ClientEffect, Decision, DecisionError, DecisionKind, DropScope,
        DropSpec, Handler, HandlerContext, HandlerOutcome, HandlerPhase, HandlerResult,
        HttpResponseSpec, PatchOp, PatchSet, StreamSlot, UpstreamEffect,
    },
    intercept::{InterceptSpec, TimeoutAction},
    observability::AuditEvent,
    session::{
        CloseReason, IngressSource, ProcessingMode, ProtocolHint, Session, SessionId, SessionState,
        TargetAddr, TlsPolicy,
    },
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
        stream: StreamSlot::Raw(loopback_stream()),
        pending_patches: PatchSet::default(),
        pause: None,
        drop_action: None,
        mock_response: None,
        audit_events: Vec::new(),
        raw_tunnel_report: None,
    }
}

fn loopback_stream() -> TcpStream {
    connected_stream_pair().0
}

fn connected_stream_pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).unwrap();
    let addr = listener.local_addr().unwrap();
    let client = TcpStream::connect(addr).unwrap();
    let (server, _) = listener.accept().unwrap();

    (server, client)
}

fn classifier_context_with_downstream_bytes(prefix: &[u8]) -> HandlerContext {
    let (server, mut client) = connected_stream_pair();
    client.write_all(prefix).unwrap();
    let mut ctx = context(HandlerPhase::Connect);
    ctx.session.set_state(SessionState::ConnectAccepted);
    ctx.stream = StreamSlot::Raw(server);
    ctx
}

fn take_peeked_stream(ctx: &mut HandlerContext) -> (Vec<u8>, TcpStream) {
    match ctx.stream.take() {
        StreamSlot::Peeked { prefix, stream } => (prefix, stream),
        other => panic!("expected peeked stream, got {other:?}"),
    }
}

fn replay_all(prefix: Vec<u8>, stream: TcpStream) -> Vec<u8> {
    let mut replay = ReplayStream::new(prefix, stream);
    let mut output = Vec::new();
    replay.read_to_end(&mut output).unwrap();
    output
}

#[test]
fn stream_slot_take_leaves_closed_slot_and_returns_owned_stream() {
    let stream = loopback_stream();
    let mut slot = StreamSlot::Peeked {
        prefix: b"abc".to_vec(),
        stream,
    };

    let taken = slot.take();

    assert!(matches!(slot, StreamSlot::Closed));
    let (prefix, _) = taken
        .into_replay_parts()
        .expect("peeked stream can be replayed");
    assert_eq!(prefix, b"abc".to_vec());
}

#[test]
fn stream_slot_into_replay_parts_supports_pre_tls_stream_states() {
    let raw = StreamSlot::Raw(loopback_stream());
    let (raw_prefix, _) = raw.into_replay_parts().expect("raw stream can replay");
    assert!(raw_prefix.is_empty());

    let peeked = StreamSlot::Peeked {
        prefix: b"prefix".to_vec(),
        stream: loopback_stream(),
    };
    let (peeked_prefix, _) = peeked
        .into_replay_parts()
        .expect("peeked stream can replay");
    assert_eq!(peeked_prefix, b"prefix".to_vec());

    let client_hello = StreamSlot::TlsClientHelloParsed {
        raw_client_hello: b"client-hello".to_vec(),
        stream: loopback_stream(),
    };
    let (client_hello_prefix, _) = client_hello
        .into_replay_parts()
        .expect("client hello stream can replay");
    assert_eq!(client_hello_prefix, b"client-hello".to_vec());
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

#[test]
fn protocol_classifier_handler_stops_and_closes_on_incomplete_eof() {
    let classifier = ProtocolClassifierHandler::new();
    let mut ctx = classifier_context_with_downstream_bytes(b"G");
    let after_classifier = FixedHandler::new("after-classifier", None, HandlerResult::Continue);

    run_handler_chain(&mut ctx, &[&classifier, &after_classifier]).unwrap();

    assert_eq!(after_classifier.calls(), 0);
    assert_eq!(ctx.session.state(), SessionState::Closed);
    assert_eq!(ctx.session.mode(), ProcessingMode::Closed);
    assert_eq!(ctx.session.close_reason(), Some(CloseReason::ProtocolError));
    assert!(matches!(ctx.stream, StreamSlot::Closed));
}

#[test]
fn protocol_classifier_handler_classifies_http1_as_inspectable_stream() {
    let prefix = b"GET / HTTP/1.1\r\n".to_vec();
    let classifier = ProtocolClassifierHandler::new();
    let mut ctx = classifier_context_with_downstream_bytes(&prefix);

    run_handler_chain(&mut ctx, &[&classifier]).unwrap();

    assert_eq!(ctx.session.protocol(), ProtocolHint::Http1);
    assert_eq!(ctx.session.mode(), ProcessingMode::Inspect);
    assert_eq!(ctx.session.state(), SessionState::InspectingHttp);
    assert!(ctx.session.tags().contains("proto:http1"));
    assert!(ctx.session.tags().contains("mode:inspect"));
    assert!(ctx.session.tags().contains("state:inspecting_http"));
    let (peeked, stream) = take_peeked_stream(&mut ctx);
    assert_eq!(replay_all(peeked, stream), prefix);
}

#[test]
fn protocol_classifier_handler_classifies_tls_without_tls_policy() {
    let prefix = [0x16, 0x03, 0x03, 0x00, 0x2e, 0x01, 0x00, 0x00].to_vec();
    let classifier = ProtocolClassifierHandler::new();
    let mut ctx = classifier_context_with_downstream_bytes(&prefix);

    run_handler_chain(&mut ctx, &[&classifier]).unwrap();

    assert_eq!(ctx.session.protocol(), ProtocolHint::Tls);
    assert_eq!(ctx.session.mode(), ProcessingMode::Inspect);
    assert_eq!(ctx.session.state(), SessionState::Classifying);
    assert_eq!(ctx.session.tls_policy(), TlsPolicy::Undecided);
    assert!(ctx.session.tags().contains("proto:tls"));
    assert!(ctx.session.tags().contains("transport:tls"));
    assert!(ctx.session.tags().contains("tls:undecided"));
    let (peeked, stream) = take_peeked_stream(&mut ctx);
    assert_eq!(replay_all(peeked, stream), prefix);
}

#[test]
fn protocol_classifier_handler_classifies_h2c_as_raw_tunnel() {
    let prefix = H2C_PRIOR_KNOWLEDGE.to_vec();
    let classifier = ProtocolClassifierHandler::new();
    let mut ctx = classifier_context_with_downstream_bytes(&prefix);

    run_handler_chain(&mut ctx, &[&classifier]).unwrap();

    assert_eq!(ctx.session.protocol(), ProtocolHint::H2c);
    assert_eq!(ctx.session.mode(), ProcessingMode::RawTunnel);
    assert_eq!(ctx.session.state(), SessionState::RawTunneling);
    assert!(ctx.session.tags().contains("proto:h2c"));
    assert!(ctx.session.tags().contains("mode:raw_tunnel"));
    assert!(ctx.session.tags().contains("state:raw_tunneling"));
    let (peeked, stream) = take_peeked_stream(&mut ctx);
    assert_eq!(replay_all(peeked, stream), prefix);
}

#[test]
fn protocol_classifier_handler_classifies_raw_tcp_as_raw_tunnel() {
    let prefix = b"SSH-2.0-openssh\r\n".to_vec();
    let classifier = ProtocolClassifierHandler::new();
    let mut ctx = classifier_context_with_downstream_bytes(&prefix);

    run_handler_chain(&mut ctx, &[&classifier]).unwrap();

    assert_eq!(ctx.session.protocol(), ProtocolHint::RawTcp);
    assert_eq!(ctx.session.mode(), ProcessingMode::RawTunnel);
    assert_eq!(ctx.session.state(), SessionState::RawTunneling);
    assert!(ctx.session.tags().contains("proto:raw_tcp"));
    assert!(ctx.session.tags().contains("mode:raw_tunnel"));
    assert!(ctx.session.tags().contains("state:raw_tunneling"));
    let (peeked, stream) = take_peeked_stream(&mut ctx);
    assert_eq!(replay_all(peeked, stream), prefix);
}
