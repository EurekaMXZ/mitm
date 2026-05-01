//! SOCKS5 negotiation, authentication, CONNECT parsing, and reply mapping.

#![allow(clippy::module_name_repetitions)]

use std::{
    error::Error,
    fmt,
    io::{self, Read, Write},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    str,
};

use crate::session::{
    CloseReason, IngressSource, Session, SessionError, SessionId, SessionState, TargetAddr,
    TargetHost,
};

/// SOCKS5 protocol version byte.
pub const SOCKS5_VERSION: u8 = 0x05;

/// SOCKS5 authentication method advertised during method negotiation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AuthMethod {
    /// No authentication is required.
    NoAuth,
    /// Username and password authentication.
    UsernamePassword,
    /// No acceptable method marker used by server replies.
    NoAcceptable,
    /// Any method value not modeled by this crate.
    Other(u8),
}

impl AuthMethod {
    /// Returns the wire byte for this authentication method.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::NoAuth => 0x00,
            Self::UsernamePassword => 0x02,
            Self::NoAcceptable => 0xff,
            Self::Other(value) => value,
        }
    }

    /// Creates an authentication method from its wire byte.
    #[must_use]
    pub const fn from_u8(value: u8) -> Self {
        match value {
            0x00 => Self::NoAuth,
            0x02 => Self::UsernamePassword,
            0xff => Self::NoAcceptable,
            other => Self::Other(other),
        }
    }
}

/// Client SOCKS5 method negotiation request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MethodNegotiation {
    /// Authentication methods advertised by the client.
    pub methods: Vec<AuthMethod>,
}

/// Username and password credentials reserved for RFC 1929 authentication.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsernamePasswordCredentials {
    /// Raw username bytes supplied by the client.
    pub username: Vec<u8>,
    /// Raw password bytes supplied by the client.
    pub password: Vec<u8>,
}

/// SOCKS5 command byte in a client request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Socks5Command {
    /// Establish a TCP connection to the requested target.
    Connect,
    /// Bind command.
    Bind,
    /// UDP associate command.
    UdpAssociate,
    /// Any command value not modeled by this crate.
    Other(u8),
}

impl Socks5Command {
    /// Creates a SOCKS5 command from its wire byte.
    #[must_use]
    pub const fn from_u8(value: u8) -> Self {
        match value {
            0x01 => Self::Connect,
            0x02 => Self::Bind,
            0x03 => Self::UdpAssociate,
            other => Self::Other(other),
        }
    }
}

/// SOCKS5 address type byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AddressType {
    /// IPv4 address.
    Ipv4,
    /// Domain name address.
    Domain,
    /// IPv6 address.
    Ipv6,
    /// Any address type value not modeled by this crate.
    Other(u8),
}

impl AddressType {
    /// Creates an address type from its wire byte.
    #[must_use]
    pub const fn from_u8(value: u8) -> Self {
        match value {
            0x01 => Self::Ipv4,
            0x03 => Self::Domain,
            0x04 => Self::Ipv6,
            other => Self::Other(other),
        }
    }

    /// Returns the wire byte for this address type.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::Ipv4 => 0x01,
            Self::Domain => 0x03,
            Self::Ipv6 => 0x04,
            Self::Other(value) => value,
        }
    }
}

/// Parsed SOCKS5 client request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Socks5Request {
    /// Command requested by the client.
    pub command: Socks5Command,
    /// Target address requested by the client.
    pub target: TargetAddr,
}

/// SOCKS5 server reply code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Socks5ReplyCode {
    /// Request succeeded.
    Succeeded,
    /// General SOCKS server failure.
    GeneralFailure,
    /// Connection not allowed by ruleset.
    ConnectionNotAllowed,
    /// Network unreachable.
    NetworkUnreachable,
    /// Host unreachable.
    HostUnreachable,
    /// Connection refused.
    ConnectionRefused,
    /// TTL expired.
    TtlExpired,
    /// Command not supported.
    CommandNotSupported,
    /// Address type not supported.
    AddressTypeNotSupported,
}

impl Socks5ReplyCode {
    /// Returns the RFC 1928 wire byte for this reply code.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::Succeeded => 0x00,
            Self::GeneralFailure => 0x01,
            Self::ConnectionNotAllowed => 0x02,
            Self::NetworkUnreachable => 0x03,
            Self::HostUnreachable => 0x04,
            Self::ConnectionRefused => 0x05,
            Self::TtlExpired => 0x06,
            Self::CommandNotSupported => 0x07,
            Self::AddressTypeNotSupported => 0x08,
        }
    }
}

/// Error returned while parsing or selecting SOCKS5 protocol values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Socks5Error {
    /// The version byte is not SOCKS5.
    InvalidVersion,
    /// The method list is empty or has extra bytes.
    InvalidMethodList,
    /// The client did not offer any authentication method accepted by core.
    NoAcceptableAuthMethod,
    /// The request command is not supported by this stage.
    UnsupportedCommand,
    /// The request address type is not supported by this stage.
    UnsupportedAddressType,
    /// The reserved byte is not zero.
    InvalidReservedByte,
    /// The domain name is empty, malformed, or rejected by target validation.
    InvalidDomain,
    /// The target port is invalid.
    InvalidPort,
    /// The input ended before the current frame could be parsed exactly.
    Truncated,
}

impl fmt::Display for Socks5Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidVersion => "invalid SOCKS5 version",
            Self::InvalidMethodList => "invalid SOCKS5 authentication method list",
            Self::NoAcceptableAuthMethod => "no acceptable SOCKS5 authentication method",
            Self::UnsupportedCommand => "unsupported SOCKS5 command",
            Self::UnsupportedAddressType => "unsupported SOCKS5 address type",
            Self::InvalidReservedByte => "invalid SOCKS5 reserved byte",
            Self::InvalidDomain => "invalid SOCKS5 domain",
            Self::InvalidPort => "invalid SOCKS5 port",
            Self::Truncated => "truncated SOCKS5 frame",
        };
        f.write_str(message)
    }
}

impl Error for Socks5Error {}

/// Session initialization decision returned by the connect policy point.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SessionInitDecision {
    /// Accept the initialized SOCKS5 session and send a success reply.
    Accept,
    /// Reject the initialized SOCKS5 session before the success reply.
    Reject {
        /// SOCKS5 reply code sent to the client.
        reply_code: Socks5ReplyCode,
        /// Close reason recorded on the rejected session.
        close_reason: CloseReason,
    },
}

/// Accepted SOCKS5 session and its parsed CONNECT request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptedSocks5Session {
    /// Session created from the SOCKS5 CONNECT request.
    pub session: Session,
    /// Parsed SOCKS5 CONNECT request.
    pub request: Socks5Request,
}

/// Rejected SOCKS5 ingress result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RejectedSocks5Session {
    /// Session state when rejection happened after session creation.
    pub session: Option<Session>,
    /// Protocol error that caused rejection before policy handling.
    pub error: Option<Socks5Error>,
    /// SOCKS5 reply code associated with the rejection.
    pub reply_code: Socks5ReplyCode,
    /// Close reason recorded when rejection happened after session creation.
    pub close_reason: Option<CloseReason>,
}

/// Result of a SOCKS5 ingress handshake.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Socks5IngressOutcome {
    /// SOCKS5 CONNECT was accepted and a session was initialized.
    Accepted(AcceptedSocks5Session),
    /// SOCKS5 CONNECT was rejected as a protocol or policy decision.
    Rejected(RejectedSocks5Session),
}

/// Error returned by the blocking SOCKS5 ingress adapter.
#[derive(Debug)]
pub enum Socks5IngressError {
    /// Blocking stream read or write failed.
    Io(io::Error),
    /// Listener address could not be encoded as a SOCKS5 reply bind address.
    InvalidBindAddress,
}

impl fmt::Display for Socks5IngressError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "SOCKS5 ingress I/O error: {error}"),
            Self::InvalidBindAddress => f.write_str("invalid SOCKS5 reply bind address"),
        }
    }
}

impl Error for Socks5IngressError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::InvalidBindAddress => None,
        }
    }
}

impl From<io::Error> for Socks5IngressError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

/// Blocking SOCKS5 ingress adapter.
#[derive(Debug, Clone)]
pub struct Socks5Ingress {
    listener: SocketAddr,
    reply_bind: TargetAddr,
}

impl Socks5Ingress {
    /// Creates a SOCKS5 ingress adapter for a listener address.
    ///
    /// The listener address is encoded as the bind address used in SOCKS5
    /// replies.
    ///
    /// # Errors
    ///
    /// Returns [`Socks5IngressError::InvalidBindAddress`] when the listener port
    /// is zero.
    pub fn new(listener: SocketAddr) -> Result<Self, Socks5IngressError> {
        let reply_bind = TargetAddr::ip(listener.ip(), listener.port())
            .map_err(|_| Socks5IngressError::InvalidBindAddress)?;

        Ok(Self {
            listener,
            reply_bind,
        })
    }

    /// Performs method negotiation, CONNECT parsing, and session initialization.
    ///
    /// Protocol rejections are returned as [`Socks5IngressOutcome::Rejected`].
    /// Blocking stream read or write failures are returned as
    /// [`Socks5IngressError::Io`].
    ///
    /// # Errors
    ///
    /// Returns [`Socks5IngressError::Io`] when reading from `reader`, writing to
    /// `writer`, or flushing `writer` fails.
    pub fn accept<R, W, F>(
        &self,
        reader: &mut R,
        writer: &mut W,
        session_id: SessionId,
        client: SocketAddr,
        policy: F,
    ) -> Result<Socks5IngressOutcome, Socks5IngressError>
    where
        R: Read,
        W: Write,
        F: FnOnce(&mut Session) -> SessionInitDecision,
    {
        let negotiation_frame = match read_method_negotiation_frame(reader)? {
            Ok(frame) => frame,
            Err(error) => return Ok(rejected_without_session(error)),
        };
        let negotiation = match parse_method_negotiation(&negotiation_frame) {
            Ok(negotiation) => negotiation,
            Err(error) => return Ok(rejected_without_session(error)),
        };

        match select_auth_method(&negotiation) {
            Ok(method) => write_and_flush(writer, &encode_method_selection(method))?,
            Err(error) => {
                write_and_flush(writer, &encode_method_selection(AuthMethod::NoAcceptable))?;
                return Ok(rejected_without_session(error));
            }
        }

        let request = match read_connect_request(reader)? {
            Ok(request) => request,
            Err(error) => {
                let reply_code = reply_code_for_error(&error);
                write_reply(writer, reply_code, &self.reply_bind)?;
                return Ok(rejected_without_session(error));
            }
        };

        let source = IngressSource::Socks5 {
            listener: self.listener,
            client,
        };
        let mut session = Session::new(session_id, client, request.target.clone(), source);
        session.set_state(SessionState::Socks5Negotiated);

        match policy(&mut session) {
            SessionInitDecision::Accept => {
                session.set_state(SessionState::ConnectAccepted);
                write_reply(writer, Socks5ReplyCode::Succeeded, &self.reply_bind)?;
                Ok(Socks5IngressOutcome::Accepted(AcceptedSocks5Session {
                    session,
                    request,
                }))
            }
            SessionInitDecision::Reject {
                reply_code,
                close_reason,
            } => {
                let reply_code = normalized_reject_reply_code(reply_code);
                session.close(close_reason);
                write_reply(writer, reply_code, &self.reply_bind)?;
                Ok(Socks5IngressOutcome::Rejected(RejectedSocks5Session {
                    session: Some(session),
                    error: None,
                    reply_code,
                    close_reason: Some(close_reason),
                }))
            }
        }
    }
}

/// Parses a SOCKS5 method negotiation frame.
///
/// The input must match `[VER, NMETHODS, METHODS...]` exactly.
///
/// # Errors
///
/// Returns [`Socks5Error::InvalidVersion`] when `VER` is not `0x05`;
/// [`Socks5Error::InvalidMethodList`] when `NMETHODS` is zero or the frame has
/// extra method bytes; and [`Socks5Error::Truncated`] when the frame is shorter
/// than advertised.
pub fn parse_method_negotiation(input: &[u8]) -> Result<MethodNegotiation, Socks5Error> {
    let version = *input.first().ok_or(Socks5Error::Truncated)?;
    if version != SOCKS5_VERSION {
        return Err(Socks5Error::InvalidVersion);
    }

    let method_count = usize::from(*input.get(1).ok_or(Socks5Error::Truncated)?);
    if method_count == 0 {
        return Err(Socks5Error::InvalidMethodList);
    }

    let expected_len = 2 + method_count;
    match input.len().cmp(&expected_len) {
        std::cmp::Ordering::Less => Err(Socks5Error::Truncated),
        std::cmp::Ordering::Greater => Err(Socks5Error::InvalidMethodList),
        std::cmp::Ordering::Equal => Ok(MethodNegotiation {
            methods: input[2..]
                .iter()
                .copied()
                .map(AuthMethod::from_u8)
                .collect(),
        }),
    }
}

/// Selects the currently supported authentication method.
///
/// This stage only accepts [`AuthMethod::NoAuth`].
///
/// # Errors
///
/// Returns [`Socks5Error::NoAcceptableAuthMethod`] when no `NoAuth` method is
/// present.
pub fn select_auth_method(negotiation: &MethodNegotiation) -> Result<AuthMethod, Socks5Error> {
    negotiation
        .methods
        .contains(&AuthMethod::NoAuth)
        .then_some(AuthMethod::NoAuth)
        .ok_or(Socks5Error::NoAcceptableAuthMethod)
}

/// Encodes a SOCKS5 method selection frame.
#[must_use]
pub const fn encode_method_selection(method: AuthMethod) -> [u8; 2] {
    [SOCKS5_VERSION, method.as_u8()]
}

/// Parses a SOCKS5 CONNECT request frame.
///
/// The input must match `[VER, CMD, RSV, ATYP, DST.ADDR, DST.PORT]` exactly.
/// This stage accepts only [`Socks5Command::Connect`] and supports IPv4,
/// domain, and IPv6 targets.
///
/// # Errors
///
/// Returns a [`Socks5Error`] when the version, command, reserved byte, address
/// type, target address, port, or frame length is invalid.
pub fn parse_connect_request(input: &[u8]) -> Result<Socks5Request, Socks5Error> {
    let version = *input.first().ok_or(Socks5Error::Truncated)?;
    if version != SOCKS5_VERSION {
        return Err(Socks5Error::InvalidVersion);
    }

    if input.len() < 4 {
        return Err(Socks5Error::Truncated);
    }

    let command = Socks5Command::from_u8(input[1]);
    if command != Socks5Command::Connect {
        return Err(Socks5Error::UnsupportedCommand);
    }

    if input[2] != 0x00 {
        return Err(Socks5Error::InvalidReservedByte);
    }

    let target = match AddressType::from_u8(input[3]) {
        AddressType::Ipv4 => parse_ipv4_target(input)?,
        AddressType::Domain => parse_domain_target(input)?,
        AddressType::Ipv6 => parse_ipv6_target(input)?,
        AddressType::Other(_) => return Err(Socks5Error::UnsupportedAddressType),
    };

    Ok(Socks5Request { command, target })
}

/// Encodes a SOCKS5 reply frame.
#[must_use]
pub fn encode_reply(code: Socks5ReplyCode, bind: &TargetAddr) -> Vec<u8> {
    let mut reply = vec![SOCKS5_VERSION, code.as_u8(), 0x00];

    match bind.host() {
        TargetHost::Ip(IpAddr::V4(ip)) => {
            reply.push(AddressType::Ipv4.as_u8());
            reply.extend_from_slice(&ip.octets());
        }
        TargetHost::Domain(domain) => {
            let domain_bytes = domain.as_bytes();
            let domain_len = u8::try_from(domain_bytes.len()).unwrap_or(u8::MAX);
            reply.push(AddressType::Domain.as_u8());
            reply.push(domain_len);
            reply.extend_from_slice(&domain_bytes[..usize::from(domain_len)]);
        }
        TargetHost::Ip(IpAddr::V6(ip)) => {
            reply.push(AddressType::Ipv6.as_u8());
            reply.extend_from_slice(&ip.octets());
        }
    }

    reply.extend_from_slice(&bind.port().to_be_bytes());
    reply
}

/// Maps a SOCKS5 parser or selection error to a server reply code.
#[must_use]
pub const fn reply_code_for_error(error: &Socks5Error) -> Socks5ReplyCode {
    match error {
        Socks5Error::UnsupportedCommand => Socks5ReplyCode::CommandNotSupported,
        Socks5Error::UnsupportedAddressType => Socks5ReplyCode::AddressTypeNotSupported,
        Socks5Error::InvalidVersion
        | Socks5Error::InvalidMethodList
        | Socks5Error::NoAcceptableAuthMethod
        | Socks5Error::InvalidReservedByte
        | Socks5Error::InvalidDomain
        | Socks5Error::InvalidPort
        | Socks5Error::Truncated => Socks5ReplyCode::GeneralFailure,
    }
}

fn read_method_negotiation_frame<R: Read>(
    reader: &mut R,
) -> Result<Result<Vec<u8>, Socks5Error>, Socks5IngressError> {
    let mut header = [0_u8; 2];
    if let Err(error) = read_protocol_exact(reader, &mut header)? {
        return Ok(Err(error));
    }

    if header[0] != SOCKS5_VERSION {
        return Ok(Err(Socks5Error::InvalidVersion));
    }

    let method_count = usize::from(header[1]);
    if method_count == 0 {
        return Ok(Err(Socks5Error::InvalidMethodList));
    }

    let mut frame = Vec::with_capacity(2 + method_count);
    frame.extend_from_slice(&header);

    let mut methods = vec![0_u8; method_count];
    if let Err(error) = read_protocol_exact(reader, &mut methods)? {
        return Ok(Err(error));
    }
    frame.extend_from_slice(&methods);

    Ok(Ok(frame))
}

fn read_connect_request<R: Read>(
    reader: &mut R,
) -> Result<Result<Socks5Request, Socks5Error>, Socks5IngressError> {
    let mut header = [0_u8; 4];
    if let Err(error) = read_protocol_exact(reader, &mut header)? {
        return Ok(Err(error));
    }

    if let Some(error) = connect_header_error(header) {
        return Ok(Err(error));
    }

    let mut frame = Vec::from(header);
    match AddressType::from_u8(header[3]) {
        AddressType::Ipv4 => {
            if let Err(error) = read_remaining(reader, &mut frame, 6)? {
                return Ok(Err(error));
            }
        }
        AddressType::Domain => {
            if let Err(error) = read_remaining(reader, &mut frame, 1)? {
                return Ok(Err(error));
            }
            let domain_len = usize::from(frame[4]);
            if domain_len == 0 {
                return Ok(Err(Socks5Error::InvalidDomain));
            }
            if let Err(error) = read_remaining(reader, &mut frame, domain_len + 2)? {
                return Ok(Err(error));
            }
        }
        AddressType::Ipv6 => {
            if let Err(error) = read_remaining(reader, &mut frame, 18)? {
                return Ok(Err(error));
            }
        }
        AddressType::Other(_) => return Ok(Err(Socks5Error::UnsupportedAddressType)),
    }

    Ok(parse_connect_request(&frame))
}

fn connect_header_error(header: [u8; 4]) -> Option<Socks5Error> {
    if header[0] != SOCKS5_VERSION {
        Some(Socks5Error::InvalidVersion)
    } else if Socks5Command::from_u8(header[1]) != Socks5Command::Connect {
        Some(Socks5Error::UnsupportedCommand)
    } else if header[2] != 0x00 {
        Some(Socks5Error::InvalidReservedByte)
    } else {
        None
    }
}

fn read_remaining<R: Read>(
    reader: &mut R,
    frame: &mut Vec<u8>,
    len: usize,
) -> Result<Result<(), Socks5Error>, Socks5IngressError> {
    let start = frame.len();
    frame.resize(start + len, 0);
    read_protocol_exact(reader, &mut frame[start..])
}

fn read_protocol_exact<R: Read>(
    reader: &mut R,
    buf: &mut [u8],
) -> Result<Result<(), Socks5Error>, Socks5IngressError> {
    match reader.read_exact(buf) {
        Ok(()) => Ok(Ok(())),
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {
            Ok(Err(Socks5Error::Truncated))
        }
        Err(error) => Err(Socks5IngressError::Io(error)),
    }
}

fn write_reply<W: Write>(
    writer: &mut W,
    reply_code: Socks5ReplyCode,
    bind: &TargetAddr,
) -> Result<(), Socks5IngressError> {
    let reply = encode_reply(reply_code, bind);
    write_and_flush(writer, &reply)
}

fn write_and_flush<W: Write>(writer: &mut W, frame: &[u8]) -> Result<(), Socks5IngressError> {
    writer.write_all(frame)?;
    writer.flush()?;
    Ok(())
}

fn rejected_without_session(error: Socks5Error) -> Socks5IngressOutcome {
    Socks5IngressOutcome::Rejected(RejectedSocks5Session {
        session: None,
        error: Some(error),
        reply_code: reply_code_for_error(&error),
        close_reason: None,
    })
}

const fn normalized_reject_reply_code(reply_code: Socks5ReplyCode) -> Socks5ReplyCode {
    match reply_code {
        Socks5ReplyCode::Succeeded => Socks5ReplyCode::GeneralFailure,
        other => other,
    }
}

fn parse_ipv4_target(input: &[u8]) -> Result<TargetAddr, Socks5Error> {
    require_exact_len(input, 10)?;

    let ip = Ipv4Addr::new(input[4], input[5], input[6], input[7]);
    let port = read_port(input, 8)?;

    TargetAddr::ip(IpAddr::V4(ip), port).map_err(map_session_error)
}

fn parse_domain_target(input: &[u8]) -> Result<TargetAddr, Socks5Error> {
    let domain_len = usize::from(*input.get(4).ok_or(Socks5Error::Truncated)?);
    if domain_len == 0 {
        return Err(Socks5Error::InvalidDomain);
    }

    let expected_len = 5 + domain_len + 2;
    require_exact_len(input, expected_len)?;

    let domain_bytes = &input[5..5 + domain_len];
    let domain = str::from_utf8(domain_bytes).map_err(|_| Socks5Error::InvalidDomain)?;
    let port = read_port(input, 5 + domain_len)?;

    TargetAddr::domain(domain.to_owned(), port).map_err(map_session_error)
}

fn parse_ipv6_target(input: &[u8]) -> Result<TargetAddr, Socks5Error> {
    require_exact_len(input, 22)?;

    let mut octets = [0_u8; 16];
    octets.copy_from_slice(&input[4..20]);
    let port = read_port(input, 20)?;

    TargetAddr::ip(IpAddr::V6(Ipv6Addr::from(octets)), port).map_err(map_session_error)
}

const fn require_exact_len(input: &[u8], expected_len: usize) -> Result<(), Socks5Error> {
    if input.len() == expected_len {
        Ok(())
    } else {
        Err(Socks5Error::Truncated)
    }
}

fn read_port(input: &[u8], offset: usize) -> Result<u16, Socks5Error> {
    let bytes = input
        .get(offset..offset + 2)
        .ok_or(Socks5Error::Truncated)?;
    Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
}

const fn map_session_error(error: SessionError) -> Socks5Error {
    match error {
        SessionError::InvalidDomain => Socks5Error::InvalidDomain,
        SessionError::InvalidPort => Socks5Error::InvalidPort,
    }
}
