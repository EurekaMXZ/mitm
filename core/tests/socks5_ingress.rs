//! SOCKS5 ingress handshake and session initialization tests.

use std::{
    cell::RefCell,
    io::{Cursor, ErrorKind, Read, Write},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    rc::Rc,
};

use mitm_core::{
    session::{CloseReason, IngressSource, SessionId, SessionState, TargetAddr},
    socks5::{
        AcceptedSocks5Session, RejectedSocks5Session, SessionInitDecision, Socks5Command,
        Socks5Error, Socks5Ingress, Socks5IngressError, Socks5IngressOutcome, Socks5ReplyCode,
    },
};

mod socks5_ingress {
    use super::*;

    #[test]
    fn successful_accept_negotiates_no_auth_parses_connect_and_replies_after_policy() {
        let listener = SocketAddr::from(([127, 0, 0, 1], 1080));
        let client = SocketAddr::from(([127, 0, 0, 1], 50_000));
        let mut reader = Cursor::new(
            [
                &[0x05, 0x01, 0x00][..],
                &[0x05, 0x01, 0x00, 0x01, 93, 184, 216, 34, 0x00, 0x50],
            ]
            .concat(),
        );
        let written = Rc::new(RefCell::new(Vec::new()));
        let mut writer = SharedWriter::new(Rc::clone(&written));
        let ingress = Socks5Ingress::new(listener).unwrap();
        let expected_target =
            TargetAddr::ip(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)), 80).unwrap();

        let outcome = ingress
            .accept(
                &mut reader,
                &mut writer,
                SessionId::new(1),
                client,
                |session| {
                    assert_eq!(session.state(), SessionState::Socks5Negotiated);
                    assert_eq!(session.client_addr, client);
                    assert_eq!(session.target, expected_target);
                    assert_eq!(session.source, IngressSource::Socks5 { listener, client });
                    assert_eq!(written.borrow().as_slice(), &[0x05, 0x00]);

                    SessionInitDecision::Accept
                },
            )
            .unwrap();

        assert_eq!(
            outcome,
            Socks5IngressOutcome::Accepted(AcceptedSocks5Session {
                session: {
                    let mut session = mitm_core::session::Session::new(
                        SessionId::new(1),
                        client,
                        expected_target.clone(),
                        IngressSource::Socks5 { listener, client },
                    );
                    session.set_state(SessionState::ConnectAccepted);
                    session
                },
                request: mitm_core::socks5::Socks5Request {
                    command: mitm_core::socks5::Socks5Command::Connect,
                    target: expected_target,
                },
            })
        );
        assert_eq!(
            written.borrow().as_slice(),
            &[0x05, 0x00, 0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x04, 0x38,]
        );
    }

    #[test]
    fn ingress_io_error_is_reported_as_io_error() {
        let listener = SocketAddr::from(([127, 0, 0, 1], 1080));
        let client = SocketAddr::from(([127, 0, 0, 1], 50_011));
        let mut reader = ErrorReader {
            kind: ErrorKind::ConnectionReset,
        };
        let mut writer = Vec::new();
        let ingress = Socks5Ingress::new(listener).unwrap();

        let error = ingress
            .accept(&mut reader, &mut writer, SessionId::new(12), client, |_| {
                panic!("policy must not run after a stream read error")
            })
            .unwrap_err();

        let Socks5IngressError::Io(error) = error else {
            panic!("ordinary stream read error must be reported as I/O");
        };

        assert_eq!(error.kind(), ErrorKind::ConnectionReset);
        assert!(writer.is_empty());
    }

    #[test]
    fn domain_connect_success_path_is_accepted() {
        let listener = SocketAddr::from(([127, 0, 0, 1], 1080));
        let client = SocketAddr::from(([127, 0, 0, 1], 50_012));
        let mut reader = Cursor::new(
            [
                &[0x05, 0x01, 0x00][..],
                &[
                    0x05, 0x01, 0x00, 0x03, 0x0b, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.',
                    b'c', b'o', b'm', 0x01, 0xbb,
                ],
            ]
            .concat(),
        );
        let written = Rc::new(RefCell::new(Vec::new()));
        let mut writer = SharedWriter::new(Rc::clone(&written));
        let ingress = Socks5Ingress::new(listener).unwrap();
        let expected_target = TargetAddr::domain("example.com", 443).unwrap();

        let outcome = ingress
            .accept(
                &mut reader,
                &mut writer,
                SessionId::new(13),
                client,
                |session| {
                    assert_eq!(session.state(), SessionState::Socks5Negotiated);
                    assert_eq!(session.target, expected_target);
                    assert_eq!(written.borrow().as_slice(), &[0x05, 0x00]);

                    SessionInitDecision::Accept
                },
            )
            .unwrap();

        let Socks5IngressOutcome::Accepted(accepted) = outcome else {
            panic!("domain CONNECT must be accepted");
        };

        assert_eq!(accepted.session.state(), SessionState::ConnectAccepted);
        assert_eq!(accepted.session.target, expected_target);
        assert_eq!(accepted.request.command, Socks5Command::Connect);
        assert_eq!(accepted.request.target, expected_target);
        assert_eq!(
            written.borrow().as_slice(),
            &[0x05, 0x00, 0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x04, 0x38,]
        );
    }

    #[test]
    fn ipv6_connect_success_path_is_accepted() {
        let listener = SocketAddr::from(([127, 0, 0, 1], 1080));
        let client = SocketAddr::from(([127, 0, 0, 1], 50_013));
        let mut reader = Cursor::new(
            [
                &[0x05, 0x01, 0x00][..],
                &[
                    0x05, 0x01, 0x00, 0x04, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x50,
                ],
            ]
            .concat(),
        );
        let written = Rc::new(RefCell::new(Vec::new()));
        let mut writer = SharedWriter::new(Rc::clone(&written));
        let ingress = Socks5Ingress::new(listener).unwrap();
        let expected_target = TargetAddr::ip(
            IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1)),
            80,
        )
        .unwrap();

        let outcome = ingress
            .accept(
                &mut reader,
                &mut writer,
                SessionId::new(14),
                client,
                |session| {
                    assert_eq!(session.state(), SessionState::Socks5Negotiated);
                    assert_eq!(session.target, expected_target);
                    assert_eq!(written.borrow().as_slice(), &[0x05, 0x00]);

                    SessionInitDecision::Accept
                },
            )
            .unwrap();

        let Socks5IngressOutcome::Accepted(accepted) = outcome else {
            panic!("IPv6 CONNECT must be accepted");
        };

        assert_eq!(accepted.session.state(), SessionState::ConnectAccepted);
        assert_eq!(accepted.session.target, expected_target);
        assert_eq!(accepted.request.command, Socks5Command::Connect);
        assert_eq!(accepted.request.target, expected_target);
        assert_eq!(
            written.borrow().as_slice(),
            &[0x05, 0x00, 0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x04, 0x38,]
        );
    }

    #[test]
    fn unsupported_atyp_maps_to_address_type_not_supported_reply() {
        let listener = SocketAddr::from(([127, 0, 0, 1], 1080));
        let client = SocketAddr::from(([127, 0, 0, 1], 50_014));
        let mut reader = Cursor::new([&[0x05, 0x01, 0x00][..], &[0x05, 0x01, 0x00, 0x09]].concat());
        let mut writer = Vec::new();
        let ingress = Socks5Ingress::new(listener).unwrap();

        let outcome = ingress
            .accept(&mut reader, &mut writer, SessionId::new(15), client, |_| {
                panic!("policy must not run for unsupported address type")
            })
            .unwrap();

        assert_eq!(
            outcome,
            Socks5IngressOutcome::Rejected(RejectedSocks5Session {
                session: None,
                error: Some(Socks5Error::UnsupportedAddressType),
                reply_code: Socks5ReplyCode::AddressTypeNotSupported,
                close_reason: None,
            })
        );
        assert_eq!(
            writer,
            [0x05, 0x00, 0x05, 0x08, 0x00, 0x01, 127, 0, 0, 1, 0x04, 0x38,]
        );
    }

    #[test]
    fn no_acceptable_auth_writes_no_acceptable_and_rejects_without_session() {
        let listener = SocketAddr::from(([127, 0, 0, 1], 1080));
        let client = SocketAddr::from(([127, 0, 0, 1], 50_001));
        let mut reader = Cursor::new([0x05, 0x01, 0x02]);
        let mut writer = Vec::new();
        let ingress = Socks5Ingress::new(listener).unwrap();

        let outcome = ingress
            .accept(&mut reader, &mut writer, SessionId::new(2), client, |_| {
                SessionInitDecision::Accept
            })
            .unwrap();

        assert_eq!(
            outcome,
            Socks5IngressOutcome::Rejected(RejectedSocks5Session {
                session: None,
                error: Some(Socks5Error::NoAcceptableAuthMethod),
                reply_code: Socks5ReplyCode::GeneralFailure,
                close_reason: None,
            })
        );
        assert_eq!(writer, [0x05, 0xff]);
    }

    #[test]
    fn invalid_connect_after_negotiation_writes_failure_reply() {
        let listener = SocketAddr::from(([127, 0, 0, 1], 1080));
        let client = SocketAddr::from(([127, 0, 0, 1], 50_002));
        let mut reader = Cursor::new(
            [
                &[0x05, 0x01, 0x00][..],
                &[0x05, 0x02, 0x00, 0x01, 127, 0, 0, 1, 0x00, 0x50],
            ]
            .concat(),
        );
        let mut writer = Vec::new();
        let ingress = Socks5Ingress::new(listener).unwrap();

        let outcome = ingress
            .accept(&mut reader, &mut writer, SessionId::new(3), client, |_| {
                SessionInitDecision::Accept
            })
            .unwrap();

        assert_eq!(
            outcome,
            Socks5IngressOutcome::Rejected(RejectedSocks5Session {
                session: None,
                error: Some(Socks5Error::UnsupportedCommand),
                reply_code: Socks5ReplyCode::CommandNotSupported,
                close_reason: None,
            })
        );
        assert_eq!(
            writer,
            [0x05, 0x00, 0x05, 0x07, 0x00, 0x01, 127, 0, 0, 1, 0x04, 0x38,]
        );
    }

    #[test]
    fn invalid_connect_reserved_byte_after_negotiation_writes_general_failure_reply() {
        let listener = SocketAddr::from(([127, 0, 0, 1], 1080));
        let client = SocketAddr::from(([127, 0, 0, 1], 50_004));
        let mut reader = Cursor::new(
            [
                &[0x05, 0x01, 0x00][..],
                &[0x05, 0x01, 0x01, 0x01, 127, 0, 0, 1, 0x00, 0x50],
            ]
            .concat(),
        );
        let mut writer = Vec::new();
        let ingress = Socks5Ingress::new(listener).unwrap();

        let outcome = ingress
            .accept(&mut reader, &mut writer, SessionId::new(5), client, |_| {
                SessionInitDecision::Accept
            })
            .unwrap();

        assert_eq!(
            outcome,
            Socks5IngressOutcome::Rejected(RejectedSocks5Session {
                session: None,
                error: Some(Socks5Error::InvalidReservedByte),
                reply_code: Socks5ReplyCode::GeneralFailure,
                close_reason: None,
            })
        );
        assert_eq!(
            writer,
            [0x05, 0x00, 0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0x04, 0x38,]
        );
    }

    #[test]
    fn truncated_method_negotiation_rejects_without_writing_method_selection() {
        let listener = SocketAddr::from(([127, 0, 0, 1], 1080));
        let client = SocketAddr::from(([127, 0, 0, 1], 50_005));
        let mut reader = Cursor::new([0x05, 0x01]);
        let mut writer = Vec::new();
        let ingress = Socks5Ingress::new(listener).unwrap();

        let outcome = ingress
            .accept(&mut reader, &mut writer, SessionId::new(6), client, |_| {
                SessionInitDecision::Accept
            })
            .unwrap();

        assert_eq!(
            outcome,
            Socks5IngressOutcome::Rejected(RejectedSocks5Session {
                session: None,
                error: Some(Socks5Error::Truncated),
                reply_code: Socks5ReplyCode::GeneralFailure,
                close_reason: None,
            })
        );
        assert!(writer.is_empty());
    }

    #[test]
    fn invalid_method_negotiation_version_rejects_without_reading_methods() {
        let listener = SocketAddr::from(([127, 0, 0, 1], 1080));
        let client = SocketAddr::from(([127, 0, 0, 1], 50_008));
        let mut reader = Cursor::new([0x04, 0xff]);
        let mut writer = Vec::new();
        let ingress = Socks5Ingress::new(listener).unwrap();

        let outcome = ingress
            .accept(&mut reader, &mut writer, SessionId::new(9), client, |_| {
                SessionInitDecision::Accept
            })
            .unwrap();

        assert_eq!(
            outcome,
            Socks5IngressOutcome::Rejected(RejectedSocks5Session {
                session: None,
                error: Some(Socks5Error::InvalidVersion),
                reply_code: Socks5ReplyCode::GeneralFailure,
                close_reason: None,
            })
        );
        assert!(writer.is_empty());
    }

    #[test]
    fn empty_method_negotiation_list_rejects_without_writing_method_selection() {
        let listener = SocketAddr::from(([127, 0, 0, 1], 1080));
        let client = SocketAddr::from(([127, 0, 0, 1], 50_009));
        let mut reader = Cursor::new([0x05, 0x00]);
        let mut writer = Vec::new();
        let ingress = Socks5Ingress::new(listener).unwrap();

        let outcome = ingress
            .accept(&mut reader, &mut writer, SessionId::new(10), client, |_| {
                SessionInitDecision::Accept
            })
            .unwrap();

        assert_eq!(
            outcome,
            Socks5IngressOutcome::Rejected(RejectedSocks5Session {
                session: None,
                error: Some(Socks5Error::InvalidMethodList),
                reply_code: Socks5ReplyCode::GeneralFailure,
                close_reason: None,
            })
        );
        assert!(writer.is_empty());
    }

    #[test]
    fn truncated_connect_after_negotiation_writes_failure_reply() {
        let listener = SocketAddr::from(([127, 0, 0, 1], 1080));
        let client = SocketAddr::from(([127, 0, 0, 1], 50_006));
        let mut reader =
            Cursor::new([&[0x05, 0x01, 0x00][..], &[0x05, 0x01, 0x00, 0x01, 127]].concat());
        let mut writer = Vec::new();
        let ingress = Socks5Ingress::new(listener).unwrap();

        let outcome = ingress
            .accept(&mut reader, &mut writer, SessionId::new(7), client, |_| {
                SessionInitDecision::Accept
            })
            .unwrap();

        assert_eq!(
            outcome,
            Socks5IngressOutcome::Rejected(RejectedSocks5Session {
                session: None,
                error: Some(Socks5Error::Truncated),
                reply_code: Socks5ReplyCode::GeneralFailure,
                close_reason: None,
            })
        );
        assert_eq!(
            writer,
            [0x05, 0x00, 0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0x04, 0x38,]
        );
    }

    #[test]
    fn empty_domain_connect_after_negotiation_writes_invalid_domain_failure_reply() {
        let listener = SocketAddr::from(([127, 0, 0, 1], 1080));
        let client = SocketAddr::from(([127, 0, 0, 1], 50_010));
        let mut reader =
            Cursor::new([&[0x05, 0x01, 0x00][..], &[0x05, 0x01, 0x00, 0x03, 0x00]].concat());
        let mut writer = Vec::new();
        let ingress = Socks5Ingress::new(listener).unwrap();

        let outcome = ingress
            .accept(&mut reader, &mut writer, SessionId::new(11), client, |_| {
                SessionInitDecision::Accept
            })
            .unwrap();

        assert_eq!(
            outcome,
            Socks5IngressOutcome::Rejected(RejectedSocks5Session {
                session: None,
                error: Some(Socks5Error::InvalidDomain),
                reply_code: Socks5ReplyCode::GeneralFailure,
                close_reason: None,
            })
        );
        assert_eq!(
            writer,
            [0x05, 0x00, 0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0x04, 0x38,]
        );
    }

    #[test]
    fn policy_reject_writes_failure_and_records_close_reason() {
        let listener = SocketAddr::from(([127, 0, 0, 1], 1080));
        let client = SocketAddr::from(([127, 0, 0, 1], 50_003));
        let mut reader = Cursor::new(
            [
                &[0x05, 0x01, 0x00][..],
                &[0x05, 0x01, 0x00, 0x01, 203, 0, 113, 10, 0x01, 0xbb],
            ]
            .concat(),
        );
        let mut writer = Vec::new();
        let ingress = Socks5Ingress::new(listener).unwrap();

        let outcome = ingress
            .accept(
                &mut reader,
                &mut writer,
                SessionId::new(4),
                client,
                |session| {
                    assert_eq!(session.state(), SessionState::Socks5Negotiated);

                    SessionInitDecision::Reject {
                        reply_code: Socks5ReplyCode::ConnectionNotAllowed,
                        close_reason: CloseReason::PolicyDrop,
                    }
                },
            )
            .unwrap();

        let Socks5IngressOutcome::Rejected(rejection) = outcome else {
            panic!("policy rejection must return a rejected outcome");
        };
        let session = rejection.session.expect("rejected session must be present");

        assert_eq!(session.state(), SessionState::Closed);
        assert_eq!(session.close_reason(), Some(CloseReason::PolicyDrop));
        assert_eq!(rejection.error, None);
        assert_eq!(rejection.reply_code, Socks5ReplyCode::ConnectionNotAllowed);
        assert_eq!(rejection.close_reason, Some(CloseReason::PolicyDrop));
        assert_eq!(
            writer,
            [0x05, 0x00, 0x05, 0x02, 0x00, 0x01, 127, 0, 0, 1, 0x04, 0x38,]
        );
    }

    #[test]
    fn policy_reject_normalizes_success_reply_to_general_failure() {
        let listener = SocketAddr::from(([127, 0, 0, 1], 1080));
        let client = SocketAddr::from(([127, 0, 0, 1], 50_007));
        let mut reader = Cursor::new(
            [
                &[0x05, 0x01, 0x00][..],
                &[0x05, 0x01, 0x00, 0x01, 203, 0, 113, 10, 0x01, 0xbb],
            ]
            .concat(),
        );
        let mut writer = Vec::new();
        let ingress = Socks5Ingress::new(listener).unwrap();

        let outcome = ingress
            .accept(&mut reader, &mut writer, SessionId::new(8), client, |_| {
                SessionInitDecision::Reject {
                    reply_code: Socks5ReplyCode::Succeeded,
                    close_reason: CloseReason::PolicyDrop,
                }
            })
            .unwrap();

        let Socks5IngressOutcome::Rejected(rejection) = outcome else {
            panic!("policy rejection must return a rejected outcome");
        };

        assert_eq!(rejection.reply_code, Socks5ReplyCode::GeneralFailure);
        assert_eq!(rejection.close_reason, Some(CloseReason::PolicyDrop));
        assert_eq!(
            writer,
            [0x05, 0x00, 0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0x04, 0x38,]
        );
    }
}

#[derive(Debug)]
struct SharedWriter {
    written: Rc<RefCell<Vec<u8>>>,
}

impl SharedWriter {
    fn new(written: Rc<RefCell<Vec<u8>>>) -> Self {
        Self { written }
    }
}

impl Write for SharedWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.written.borrow_mut().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[derive(Debug)]
struct ErrorReader {
    kind: ErrorKind,
}

impl Read for ErrorReader {
    fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
        Err(std::io::Error::new(
            self.kind,
            "injected stream read failure",
        ))
    }
}
