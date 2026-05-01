//! Session tag derivation tests.

use std::net::SocketAddr;

use mitm_core::{
    session::{
        ApplicationProtocol, CloseReason, IngressSource, ProcessingMode, ProtocolHint, Session,
        SessionId, SessionState, TargetAddr, TlsPolicy,
    },
    tags::{derive_session_tags, TagSet},
};

fn test_session() -> Session {
    let client = SocketAddr::from(([127, 0, 0, 1], 50_200));
    let listener = SocketAddr::from(([127, 0, 0, 1], 1080));
    let target = TargetAddr::domain("example.com", 443).unwrap();
    let source = IngressSource::Socks5 { listener, client };

    Session::new(SessionId::new(77), client, target, source)
}

#[test]
fn session_state_and_protocol_changes_refresh_derived_tags() {
    let mut session = test_session();

    assert!(session.tags().contains("mode:inspect"));
    assert!(session.tags().contains("proto:unknown"));
    assert!(session.tags().contains("transport:tcp"));
    assert!(session.tags().contains("tls:undecided"));

    session.set_protocol(ProtocolHint::Tls);
    session.set_tls_policy(TlsPolicy::Mitm);
    session.set_application_protocol(ApplicationProtocol::Http1);

    assert!(session.tags().contains("proto:http1"));
    assert!(session.tags().contains("transport:tls"));
    assert!(session.tags().contains("tls:mitm"));
    assert!(!session.tags().contains("proto:unknown"));
    assert!(!session.tags().contains("tls:undecided"));

    session.set_protocol(ProtocolHint::RawTcp);
    session.set_mode(ProcessingMode::RawTunnel);

    assert!(session.tags().contains("mode:raw_tunnel"));
    assert!(session.tags().contains("proto:raw_tcp"));
    assert!(!session.tags().contains("mode:inspect"));

    session.close(CloseReason::PolicyDrop);

    assert!(session.tags().contains("mode:closed"));
    assert!(session.tags().contains("state:closed"));
    assert!(!session.tags().contains("mode:raw_tunnel"));
}

#[test]
fn derive_session_tags_exposes_core_mode_protocol_transport_and_tls_tags() {
    let tags = derive_session_tags(
        SessionState::InspectingHttp,
        ProcessingMode::Inspect,
        ProtocolHint::Tls,
        TlsPolicy::Bypass,
        ApplicationProtocol::Unknown,
    );

    assert!(tags.contains("state:inspecting_http"));
    assert!(tags.contains("mode:inspect"));
    assert!(tags.contains("proto:tls"));
    assert!(tags.contains("transport:tls"));
    assert!(tags.contains("tls:bypass"));
}

#[test]
fn tag_set_keeps_single_value_namespaces_mutually_exclusive() {
    let mut tags = TagSet::new();

    tags.insert("mode:inspect");
    tags.insert("mode:raw_tunnel");
    tags.insert("upstream:connected");
    tags.insert("upstream:reused");
    tags.insert("body:buffered");
    tags.insert("body:streaming");
    tags.insert("tls:mitm");
    tags.insert("tls:bypass");

    assert!(tags.contains("mode:raw_tunnel"));
    assert!(!tags.contains("mode:inspect"));
    assert!(tags.contains("upstream:reused"));
    assert!(!tags.contains("upstream:connected"));
    assert!(tags.contains("body:streaming"));
    assert!(!tags.contains("body:buffered"));
    assert!(tags.contains("tls:mitm"));
    assert!(tags.contains("tls:bypass"));
}
