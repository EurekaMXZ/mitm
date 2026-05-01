//! Decision and patch validation matrix tests.

use std::{net::IpAddr, time::Duration};

use mitm_core::{
    handler::{
        validate_decision_for_phase, validate_patch_set_for_phase, ClientEffect, Decision,
        DecisionError, DecisionKind, DropScope, DropSpec, HandlerPhase, HttpResponseSpec, PatchOp,
        PatchSet, UpstreamEffect,
    },
    intercept::{InterceptSpec, TimeoutAction},
    session::TargetAddr,
};

fn redirect_patch() -> Decision {
    Decision::Patch(PatchSet::new(vec![PatchOp::RedirectTarget {
        target: TargetAddr::domain("redirect.example", 443).unwrap(),
    }]))
}

fn request_patch() -> Decision {
    Decision::Patch(PatchSet::new(vec![
        PatchOp::SetMethod("POST".to_owned()),
        PatchOp::SetUri("/changed".to_owned()),
        PatchOp::SetHeader {
            name: "x-request".to_owned(),
            value: "1".to_owned(),
        },
        PatchOp::AppendHeader {
            name: "x-request".to_owned(),
            value: "2".to_owned(),
        },
        PatchOp::RemoveHeader {
            name: "x-remove".to_owned(),
        },
        PatchOp::ReplaceBody(b"request body".to_vec()),
    ]))
}

fn response_patch() -> Decision {
    Decision::Patch(PatchSet::new(vec![
        PatchOp::SetStatus(201),
        PatchOp::SetHeader {
            name: "x-response".to_owned(),
            value: "1".to_owned(),
        },
        PatchOp::AppendHeader {
            name: "x-response".to_owned(),
            value: "2".to_owned(),
        },
        PatchOp::RemoveHeader {
            name: "x-remove".to_owned(),
        },
        PatchOp::ReplaceBody(b"response body".to_vec()),
    ]))
}

fn pause(phase: HandlerPhase) -> Decision {
    Decision::Pause(InterceptSpec {
        phase,
        timeout: Duration::from_secs(30),
        timeout_action: TimeoutAction::FailClose,
    })
}

fn drop_session() -> Decision {
    Decision::Drop(DropSpec {
        scope: DropScope::Session,
        client_effect: ClientEffect::Close,
        upstream_effect: UpstreamEffect::NotConnected,
        reason: "policy".to_owned(),
    })
}

fn mock_response() -> Decision {
    Decision::MockResponse(HttpResponseSpec {
        status: 204,
        headers: vec![("x-mock".to_owned(), "1".to_owned())],
        body: Vec::new(),
    })
}

fn assert_allowed(phase: HandlerPhase, decision: &Decision) {
    assert_eq!(validate_decision_for_phase(phase, decision), Ok(()));
}

fn assert_rejected(phase: HandlerPhase, decision: &Decision) {
    assert!(validate_decision_for_phase(phase, decision).is_err());
}

#[test]
fn connect_phase_accepts_redirect_patch_pause_drop_and_raw_tunnel() {
    assert_allowed(HandlerPhase::Connect, &Decision::Pass);
    assert_allowed(HandlerPhase::Connect, &redirect_patch());
    assert_allowed(HandlerPhase::Connect, &pause(HandlerPhase::Connect));
    assert_allowed(HandlerPhase::Connect, &drop_session());
    assert_allowed(HandlerPhase::Connect, &Decision::SetRawTunnel);

    assert_rejected(HandlerPhase::Connect, &request_patch());
    assert_rejected(HandlerPhase::Connect, &response_patch());
    assert_rejected(HandlerPhase::Connect, &mock_response());
    assert_rejected(HandlerPhase::Connect, &Decision::SetTlsMitm);
    assert_rejected(HandlerPhase::Connect, &Decision::SetTlsBypass);
}

#[test]
fn tls_client_hello_phase_accepts_tls_policy_pause_and_drop() {
    assert_allowed(HandlerPhase::TlsClientHello, &Decision::SetTlsMitm);
    assert_allowed(HandlerPhase::TlsClientHello, &Decision::SetTlsBypass);
    assert_allowed(
        HandlerPhase::TlsClientHello,
        &pause(HandlerPhase::TlsClientHello),
    );
    assert_allowed(HandlerPhase::TlsClientHello, &drop_session());

    assert_rejected(HandlerPhase::TlsClientHello, &Decision::Pass);
    assert_rejected(HandlerPhase::TlsClientHello, &redirect_patch());
    assert_rejected(HandlerPhase::TlsClientHello, &request_patch());
    assert_rejected(HandlerPhase::TlsClientHello, &response_patch());
    assert_rejected(HandlerPhase::TlsClientHello, &mock_response());
    assert_rejected(HandlerPhase::TlsClientHello, &Decision::SetRawTunnel);
}

#[test]
fn tls_client_hello_phase_rejects_empty_patch_set() {
    assert_eq!(
        validate_decision_for_phase(
            HandlerPhase::TlsClientHello,
            &Decision::Patch(PatchSet::new(vec![]))
        ),
        Err(DecisionError::DecisionNotAllowed {
            phase: HandlerPhase::TlsClientHello,
            decision: DecisionKind::Patch,
        })
    );
}

#[test]
fn request_phases_accept_expected_patch_and_mock_response_actions() {
    let request_before = HandlerPhase::RequestBeforeIntercept;
    let request_after = HandlerPhase::RequestAfterIntercept;

    for phase in [request_before, request_after] {
        assert_allowed(phase, &Decision::Pass);
        assert_allowed(phase, &redirect_patch());
        assert_allowed(phase, &request_patch());
        assert_allowed(phase, &drop_session());
        assert_allowed(phase, &mock_response());

        assert_rejected(phase, &response_patch());
        assert_rejected(phase, &Decision::SetRawTunnel);
        assert_rejected(phase, &Decision::SetTlsMitm);
        assert_rejected(phase, &Decision::SetTlsBypass);
    }

    assert_allowed(request_before, &pause(request_before));
    assert_rejected(request_after, &pause(request_after));
}

#[test]
fn response_phases_reject_mock_response_and_tls_policy_actions() {
    let response_before = HandlerPhase::ResponseBeforeIntercept;
    let response_after = HandlerPhase::ResponseAfterIntercept;

    for phase in [response_before, response_after] {
        assert_allowed(phase, &Decision::Pass);
        assert_allowed(phase, &response_patch());
        assert_allowed(phase, &drop_session());

        assert_rejected(phase, &redirect_patch());
        assert_rejected(phase, &request_patch());
        assert_rejected(phase, &mock_response());
        assert_rejected(phase, &Decision::SetRawTunnel);
        assert_rejected(phase, &Decision::SetTlsMitm);
        assert_rejected(phase, &Decision::SetTlsBypass);
    }

    assert_allowed(response_before, &pause(response_before));
    assert_rejected(response_after, &pause(response_after));
}

#[test]
fn patch_set_validation_reports_invalid_phase_specific_patch() {
    let connect_patch = PatchSet::new(vec![PatchOp::RedirectTarget {
        target: TargetAddr::ip(IpAddr::from([127, 0, 0, 1]), 8080).unwrap(),
    }]);
    let request_patch = PatchSet::new(vec![PatchOp::SetMethod("GET".to_owned())]);
    let response_patch = PatchSet::new(vec![PatchOp::SetStatus(200)]);

    assert_eq!(
        validate_patch_set_for_phase(HandlerPhase::Connect, &connect_patch),
        Ok(())
    );
    assert!(validate_patch_set_for_phase(HandlerPhase::Connect, &request_patch).is_err());
    assert!(
        validate_patch_set_for_phase(HandlerPhase::RequestBeforeIntercept, &response_patch)
            .is_err()
    );
}

#[test]
fn patch_set_validation_rejects_tls_client_hello_phase() {
    let empty_patch = PatchSet::new(vec![]);
    let redirect_patch = PatchSet::new(vec![PatchOp::RedirectTarget {
        target: TargetAddr::domain("redirect.example", 443).unwrap(),
    }]);

    for patch in [&empty_patch, &redirect_patch] {
        assert_eq!(
            validate_patch_set_for_phase(HandlerPhase::TlsClientHello, patch),
            Err(DecisionError::DecisionNotAllowed {
                phase: HandlerPhase::TlsClientHello,
                decision: DecisionKind::Patch,
            })
        );
    }
}
