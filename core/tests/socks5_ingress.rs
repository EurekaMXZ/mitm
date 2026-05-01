//! SOCKS5 ingress handshake and session initialization tests.

use std::{
    cell::RefCell,
    io::{Cursor, Write},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    rc::Rc,
};

use mitm_core::{
    session::{CloseReason, IngressSource, SessionId, SessionState, TargetAddr},
    socks5::{
        AcceptedSocks5Session, RejectedSocks5Session, SessionInitDecision, Socks5Error,
        Socks5Ingress, Socks5IngressOutcome, Socks5ReplyCode,
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
                    assert_eq!(session.state, SessionState::Socks5Negotiated);
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
                    assert_eq!(session.state, SessionState::Socks5Negotiated);

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

        assert_eq!(session.state, SessionState::Closed);
        assert_eq!(session.close_reason, Some(CloseReason::PolicyDrop));
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
