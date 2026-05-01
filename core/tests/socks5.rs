//! SOCKS5 protocol parsing and encoding tests.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use mitm_core::{
    session::{TargetAddr, TargetHost},
    socks5::{
        encode_method_selection, encode_reply, parse_connect_request, parse_method_negotiation,
        reply_code_for_error, select_auth_method, AddressType, AuthMethod, Socks5Command,
        Socks5Error, Socks5ReplyCode,
    },
};

#[test]
fn socks5_method_negotiation_parses_multiple_methods_and_selects_no_auth() {
    let negotiation = parse_method_negotiation(&[0x05, 0x03, 0x02, 0x00, 0x80]).unwrap();

    assert_eq!(
        negotiation.methods,
        vec![
            AuthMethod::UsernamePassword,
            AuthMethod::NoAuth,
            AuthMethod::Other(0x80)
        ]
    );
    assert_eq!(select_auth_method(&negotiation), Ok(AuthMethod::NoAuth));
}

#[test]
fn socks5_method_negotiation_rejects_invalid_version_empty_methods_and_length_mismatch() {
    assert_eq!(
        parse_method_negotiation(&[0x04, 0x01, 0x00]),
        Err(Socks5Error::InvalidVersion)
    );
    assert_eq!(
        parse_method_negotiation(&[0x05, 0x00]),
        Err(Socks5Error::InvalidMethodList)
    );
    assert_eq!(
        parse_method_negotiation(&[0x05, 0x02, 0x00]),
        Err(Socks5Error::Truncated)
    );
    assert_eq!(
        parse_method_negotiation(&[0x05, 0x01, 0x00, 0x02]),
        Err(Socks5Error::InvalidMethodList)
    );
}

#[test]
fn socks5_method_selection_reports_no_acceptable_when_no_auth_is_absent() {
    let negotiation = parse_method_negotiation(&[0x05, 0x02, 0x02, 0x80]).unwrap();

    assert_eq!(
        select_auth_method(&negotiation),
        Err(Socks5Error::NoAcceptableAuthMethod)
    );
    assert_eq!(
        encode_method_selection(AuthMethod::NoAcceptable),
        [0x05, 0xff]
    );
}

#[test]
fn socks5_connect_request_parses_ipv4_target() {
    let request =
        parse_connect_request(&[0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0x1f, 0x90]).unwrap();

    assert_eq!(request.command, Socks5Command::Connect);
    assert_eq!(
        request.target,
        TargetAddr::ip(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080).unwrap()
    );
}

#[test]
fn socks5_connect_request_parses_domain_target() {
    let request = parse_connect_request(&[
        0x05, 0x01, 0x00, 0x03, 0x0b, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c', b'o',
        b'm', 0x01, 0xbb,
    ])
    .unwrap();

    assert_eq!(request.command, Socks5Command::Connect);
    assert_eq!(request.target.port(), 443);
    assert_eq!(
        request.target.host(),
        &TargetHost::Domain("example.com".to_owned())
    );
}

#[test]
fn socks5_connect_request_parses_ipv6_target() {
    let request = parse_connect_request(&[
        0x05, 0x01, 0x00, 0x04, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x50,
    ])
    .unwrap();

    assert_eq!(request.command, Socks5Command::Connect);
    assert_eq!(
        request.target,
        TargetAddr::ip(
            IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1)),
            80,
        )
        .unwrap()
    );
}

#[test]
fn socks5_connect_request_rejects_invalid_command_address_reserved_length_and_port() {
    assert_eq!(
        parse_connect_request(&[0x05, 0x02, 0x00, 0x01, 127, 0, 0, 1, 0x00, 0x50]),
        Err(Socks5Error::UnsupportedCommand)
    );
    assert_eq!(
        parse_connect_request(&[0x05, 0x01, 0x00, 0x09, 127, 0, 0, 1, 0x00, 0x50]),
        Err(Socks5Error::UnsupportedAddressType)
    );
    assert_eq!(
        parse_connect_request(&[0x05, 0x01, 0x01, 0x01, 127, 0, 0, 1, 0x00, 0x50]),
        Err(Socks5Error::InvalidReservedByte)
    );
    assert_eq!(
        parse_connect_request(&[0x05, 0x01, 0x00, 0x01, 127, 0, 0]),
        Err(Socks5Error::Truncated)
    );
    assert_eq!(
        parse_connect_request(&[0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0x00, 0x50, 0x00]),
        Err(Socks5Error::Truncated)
    );
    assert_eq!(
        parse_connect_request(&[0x05, 0x01, 0x00, 0x03, 0x00, 0x00, 0x50]),
        Err(Socks5Error::InvalidDomain)
    );
    assert_eq!(
        parse_connect_request(&[0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0x00, 0x00]),
        Err(Socks5Error::InvalidPort)
    );
}

#[test]
fn socks5_reply_codes_match_rfc_1928_values() {
    assert_eq!(Socks5ReplyCode::Succeeded.as_u8(), 0x00);
    assert_eq!(Socks5ReplyCode::GeneralFailure.as_u8(), 0x01);
    assert_eq!(Socks5ReplyCode::ConnectionNotAllowed.as_u8(), 0x02);
    assert_eq!(Socks5ReplyCode::NetworkUnreachable.as_u8(), 0x03);
    assert_eq!(Socks5ReplyCode::HostUnreachable.as_u8(), 0x04);
    assert_eq!(Socks5ReplyCode::ConnectionRefused.as_u8(), 0x05);
    assert_eq!(Socks5ReplyCode::TtlExpired.as_u8(), 0x06);
    assert_eq!(Socks5ReplyCode::CommandNotSupported.as_u8(), 0x07);
    assert_eq!(Socks5ReplyCode::AddressTypeNotSupported.as_u8(), 0x08);
}

#[test]
fn socks5_encode_reply_supports_ipv4_domain_and_ipv6_targets() {
    let ipv4 = TargetAddr::ip(IpAddr::V4(Ipv4Addr::LOCALHOST), 1080).unwrap();
    let domain = TargetAddr::domain("example.com", 443).unwrap();
    let ipv6 = TargetAddr::ip(IpAddr::V6(Ipv6Addr::LOCALHOST), 8443).unwrap();

    assert_eq!(
        encode_reply(Socks5ReplyCode::Succeeded, &ipv4),
        vec![0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x04, 0x38]
    );
    assert_eq!(
        encode_reply(Socks5ReplyCode::HostUnreachable, &domain),
        vec![
            0x05, 0x04, 0x00, 0x03, 0x0b, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c',
            b'o', b'm', 0x01, 0xbb
        ]
    );
    assert_eq!(
        encode_reply(Socks5ReplyCode::ConnectionRefused, &ipv6),
        vec![
            0x05, 0x05, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x20, 0xfb
        ]
    );
}

#[test]
fn socks5_byte_value_helpers_preserve_known_and_unknown_values() {
    assert_eq!(AuthMethod::from_u8(0x00), AuthMethod::NoAuth);
    assert_eq!(AuthMethod::from_u8(0x02), AuthMethod::UsernamePassword);
    assert_eq!(AuthMethod::from_u8(0xff), AuthMethod::NoAcceptable);
    assert_eq!(AuthMethod::Other(0x80).as_u8(), 0x80);
    assert_eq!(Socks5Command::from_u8(0x01), Socks5Command::Connect);
    assert_eq!(Socks5Command::from_u8(0x02), Socks5Command::Bind);
    assert_eq!(Socks5Command::from_u8(0x03), Socks5Command::UdpAssociate);
    assert_eq!(Socks5Command::from_u8(0x09), Socks5Command::Other(0x09));
    assert_eq!(AddressType::from_u8(0x01), AddressType::Ipv4);
    assert_eq!(AddressType::from_u8(0x03), AddressType::Domain);
    assert_eq!(AddressType::from_u8(0x04), AddressType::Ipv6);
    assert_eq!(AddressType::Other(0x09).as_u8(), 0x09);
}

#[test]
fn socks5_reply_code_for_error_maps_primary_socks5_errors() {
    assert_eq!(
        reply_code_for_error(&Socks5Error::UnsupportedCommand),
        Socks5ReplyCode::CommandNotSupported
    );
    assert_eq!(
        reply_code_for_error(&Socks5Error::UnsupportedAddressType),
        Socks5ReplyCode::AddressTypeNotSupported
    );
    assert_eq!(
        reply_code_for_error(&Socks5Error::InvalidDomain),
        Socks5ReplyCode::GeneralFailure
    );
    assert_eq!(
        reply_code_for_error(&Socks5Error::InvalidPort),
        Socks5ReplyCode::GeneralFailure
    );
    assert_eq!(
        reply_code_for_error(&Socks5Error::NoAcceptableAuthMethod),
        Socks5ReplyCode::GeneralFailure
    );
}
