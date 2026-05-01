//! Session type behavior tests.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use mitm_core::session::{
    ApplicationProtocol, CloseReason, Flow, FlowId, IngressSource, ProcessingMode, ProtocolHint,
    Session, SessionError, SessionId, SessionState, TargetAddr, TargetHost, TlsPolicy, Transaction,
    TransactionId, TransactionState,
};

#[test]
fn session_id_newtypes_preserve_values_and_compare() {
    let lower_session = SessionId::new(7);
    let higher_session = SessionId::new(11);
    let transaction = TransactionId::new(13);
    let flow = FlowId::new(17);

    assert_eq!(lower_session.get(), 7);
    assert_eq!(transaction.get(), 13);
    assert_eq!(flow.get(), 17);
    assert!(lower_session < higher_session);
}

#[test]
fn session_target_addr_supports_domain_ipv4_and_ipv6() {
    let domain = TargetAddr::domain("api-example.localhost", 443).unwrap();
    let ipv4 = TargetAddr::ip(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080).unwrap();
    let ipv6 = TargetAddr::ip(IpAddr::V6(Ipv6Addr::LOCALHOST), 8443).unwrap();

    assert_eq!(domain.port(), 443);
    assert_eq!(ipv4.port(), 8080);
    assert_eq!(ipv6.port(), 8443);
    assert_eq!(
        domain.host(),
        &TargetHost::Domain("api-example.localhost".to_owned())
    );
    assert_eq!(
        ipv4.host(),
        &TargetHost::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST))
    );
    assert_eq!(
        ipv6.host(),
        &TargetHost::Ip(IpAddr::V6(Ipv6Addr::LOCALHOST))
    );
}

#[test]
fn session_target_addr_rejects_invalid_domains_and_zero_port() {
    let sixty_four = "a".repeat(64);
    let too_long_domain = format!(
        "{}.{}.{}.{}",
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(64)
    );

    assert_eq!(TargetAddr::domain("", 80), Err(SessionError::InvalidDomain));
    assert_eq!(
        TargetAddr::domain("example..com", 80),
        Err(SessionError::InvalidDomain)
    );
    assert_eq!(
        TargetAddr::domain(format!("{sixty_four}.example"), 80),
        Err(SessionError::InvalidDomain)
    );
    assert_eq!(
        TargetAddr::domain("exa mple.com", 80),
        Err(SessionError::InvalidDomain)
    );
    assert_eq!(
        TargetAddr::domain(too_long_domain, 80),
        Err(SessionError::InvalidDomain)
    );
    assert_eq!(
        TargetAddr::domain("example.com", 0),
        Err(SessionError::InvalidPort)
    );
    assert_eq!(
        TargetAddr::ip(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        Err(SessionError::InvalidPort)
    );
}

#[test]
fn session_new_sets_default_state_and_processing_fields() {
    let client = SocketAddr::from(([127, 0, 0, 1], 50_000));
    let listener = SocketAddr::from(([127, 0, 0, 1], 1080));
    let target = TargetAddr::domain("example.com", 80).unwrap();
    let source = IngressSource::Socks5 { listener, client };

    let session = Session::new(SessionId::new(1), client, target.clone(), source);

    assert_eq!(session.id, SessionId::new(1));
    assert_eq!(session.client_addr, client);
    assert_eq!(session.target, target);
    assert_eq!(session.source, source);
    assert_eq!(session.state, SessionState::Socks5Connected);
    assert_eq!(session.protocol, ProtocolHint::Unknown);
    assert_eq!(session.mode, ProcessingMode::Inspect);
    assert_eq!(session.tls_policy, TlsPolicy::Undecided);
    assert_eq!(session.application_protocol, ApplicationProtocol::Unknown);
    assert_eq!(session.close_reason, None);
}

#[test]
fn session_close_records_reason_and_marks_closed() {
    let client = SocketAddr::from(([127, 0, 0, 1], 50_001));
    let target = TargetAddr::domain("example.com", 80).unwrap();
    let source = IngressSource::Socks5 {
        listener: SocketAddr::from(([127, 0, 0, 1], 1080)),
        client,
    };
    let mut session = Session::new(SessionId::new(2), client, target, source);

    session.close(CloseReason::PolicyDrop);

    assert_eq!(session.state, SessionState::Closed);
    assert_eq!(session.mode, ProcessingMode::Closed);
    assert_eq!(session.close_reason, Some(CloseReason::PolicyDrop));
    assert_eq!(CloseReason::PolicyDrop.to_string(), "policy drop");
}

#[test]
fn session_transaction_new_starts_reading_request() {
    let transaction = Transaction::new(TransactionId::new(3), SessionId::new(2));

    assert_eq!(transaction.id, TransactionId::new(3));
    assert_eq!(transaction.session_id, SessionId::new(2));
    assert_eq!(transaction.state, TransactionState::RequestReading);
}

#[test]
fn session_flow_constructors_associate_session_and_transaction() {
    let session_flow = Flow::for_session(FlowId::new(5), SessionId::new(2), ProtocolHint::RawTcp);
    let transaction_flow = Flow::for_transaction(
        FlowId::new(6),
        SessionId::new(2),
        TransactionId::new(3),
        ProtocolHint::Http1,
    );

    assert_eq!(session_flow.id, FlowId::new(5));
    assert_eq!(session_flow.session_id, SessionId::new(2));
    assert_eq!(session_flow.transaction_id, None);
    assert_eq!(session_flow.protocol, ProtocolHint::RawTcp);
    assert_eq!(transaction_flow.id, FlowId::new(6));
    assert_eq!(transaction_flow.session_id, SessionId::new(2));
    assert_eq!(transaction_flow.transaction_id, Some(TransactionId::new(3)));
    assert_eq!(transaction_flow.protocol, ProtocolHint::Http1);
}
