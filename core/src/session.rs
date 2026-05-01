//! Session, transaction, flow identity, and lifecycle state types.

#![allow(clippy::module_name_repetitions)]

use std::{
    error::Error,
    fmt,
    net::{IpAddr, SocketAddr},
};

use crate::tags::{derive_session_tags, TagSet};

/// Identifier for a SOCKS5 TCP connection session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SessionId(u64);

impl SessionId {
    /// Creates a session identifier from its numeric representation.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the numeric representation of this session identifier.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Identifier for a single HTTP request and response exchange.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TransactionId(u64);

impl TransactionId {
    /// Creates a transaction identifier from its numeric representation.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the numeric representation of this transaction identifier.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Identifier for a session-level or transaction-level flow record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FlowId(u64);

impl FlowId {
    /// Creates a flow identifier from its numeric representation.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the numeric representation of this flow identifier.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Host portion of a SOCKS5 CONNECT target.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TargetHost {
    /// Domain name target as provided by the client.
    Domain(String),
    /// IP address target.
    Ip(IpAddr),
}

impl TargetHost {
    /// Creates a validated domain target host.
    ///
    /// Domain validation is limited to byte length, label shape, and whitespace
    /// checks. IDNA conversion is intentionally outside this first session
    /// model.
    ///
    /// # Errors
    ///
    /// Returns [`SessionError::InvalidDomain`] when the domain is empty, longer
    /// than 255 bytes, contains an empty label, contains a label longer than 63
    /// bytes, or contains whitespace.
    pub fn domain(domain: impl Into<String>) -> Result<Self, SessionError> {
        let domain = domain.into();
        validate_domain(&domain)?;
        Ok(Self::Domain(domain))
    }
}

/// Target host and port accepted from a SOCKS5 CONNECT request.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TargetAddr {
    host: TargetHost,
    port: u16,
}

impl TargetAddr {
    /// Creates a target address from a validated domain and port.
    ///
    /// # Errors
    ///
    /// Returns [`SessionError::InvalidPort`] when `port` is zero. Returns
    /// [`SessionError::InvalidDomain`] when `domain` fails target host
    /// validation.
    pub fn domain(domain: impl Into<String>, port: u16) -> Result<Self, SessionError> {
        validate_port(port)?;
        Ok(Self {
            host: TargetHost::domain(domain)?,
            port,
        })
    }

    /// Creates a target address from an IP address and port.
    ///
    /// # Errors
    ///
    /// Returns [`SessionError::InvalidPort`] when `port` is zero.
    pub const fn ip(ip: IpAddr, port: u16) -> Result<Self, SessionError> {
        match validate_port(port) {
            Ok(()) => Ok(Self {
                host: TargetHost::Ip(ip),
                port,
            }),
            Err(error) => Err(error),
        }
    }

    /// Returns the target host.
    #[must_use]
    pub const fn host(&self) -> &TargetHost {
        &self.host
    }

    /// Returns the target port.
    #[must_use]
    pub const fn port(&self) -> u16 {
        self.port
    }
}

/// Source metadata for an accepted inbound connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IngressSource {
    /// SOCKS5 listener and client addresses.
    Socks5 {
        /// Local SOCKS5 listener address that accepted the connection.
        listener: SocketAddr,
        /// Remote client address connected to the SOCKS5 listener.
        client: SocketAddr,
    },
}

/// Connection-level protocol processing state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SessionState {
    /// TCP connection accepted by the SOCKS5 ingress.
    Socks5Connected,
    /// SOCKS5 method negotiation has completed.
    Socks5Negotiated,
    /// SOCKS5 CONNECT has been accepted.
    ConnectAccepted,
    /// Initial downstream bytes are being classified.
    Classifying,
    /// HTTP traffic is being inspected.
    InspectingHttp,
    /// Raw TCP bytes are being tunneled.
    RawTunneling,
    /// Session close has started.
    Closing,
    /// Session is closed.
    Closed,
}

/// HTTP request and response transaction state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TransactionState {
    /// Request bytes are being read.
    RequestReading,
    /// Request processing is paused.
    RequestPaused,
    /// Request is ready for upstream processing.
    RequestReady,
    /// Request has been sent or queued for upstream processing.
    UpstreamPending,
    /// Response bytes are being read.
    ResponseReading,
    /// Response processing is paused.
    ResponsePaused,
    /// Response is ready for downstream processing.
    ResponseReady,
    /// Transaction completed normally.
    Completed,
    /// Transaction was dropped by policy or protocol handling.
    Dropped,
}

/// High-level processing mode for a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProcessingMode {
    /// Inspect supported protocols.
    Inspect,
    /// Tunnel raw bytes without HTTP inspection.
    RawTunnel,
    /// Session processing is closed.
    Closed,
}

/// Protocol classification hint derived from downstream bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProtocolHint {
    /// Protocol has not been classified yet.
    Unknown,
    /// Traffic should be treated as raw TCP.
    RawTcp,
    /// HTTP/1 traffic.
    Http1,
    /// TLS traffic before MITM or bypass handling.
    Tls,
    /// HTTP/2 cleartext prior knowledge traffic.
    H2c,
}

/// TLS policy selected for a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TlsPolicy {
    /// TLS policy has not been selected yet.
    Undecided,
    /// Perform TLS MITM.
    Mitm,
    /// Bypass TLS inspection and tunnel encrypted bytes.
    Bypass,
}

/// Application protocol selected after classification or TLS negotiation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ApplicationProtocol {
    /// Application protocol is not known yet.
    Unknown,
    /// HTTP/1 application protocol.
    Http1,
    /// HTTP/2 application protocol.
    H2,
    /// Another application protocol.
    Other,
}

/// Reason recorded when a session closes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CloseReason {
    /// Client closed the downstream connection.
    ClientClosed,
    /// Upstream peer closed the upstream connection.
    UpstreamClosed,
    /// Policy explicitly dropped the session.
    PolicyDrop,
    /// Protocol parser or state machine rejected the traffic.
    ProtocolError,
    /// Session timed out.
    Timeout,
    /// Internal processing failed.
    InternalError,
}

impl fmt::Display for CloseReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let reason = match self {
            Self::ClientClosed => "client closed",
            Self::UpstreamClosed => "upstream closed",
            Self::PolicyDrop => "policy drop",
            Self::ProtocolError => "protocol error",
            Self::Timeout => "timeout",
            Self::InternalError => "internal error",
        };
        f.write_str(reason)
    }
}

/// Connection-level session metadata and lifecycle state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Session {
    /// Session identifier.
    pub id: SessionId,
    /// Remote client socket address.
    pub client_addr: SocketAddr,
    /// SOCKS5 CONNECT target.
    pub target: TargetAddr,
    /// Ingress source that accepted the session.
    pub source: IngressSource,
    /// Current session state.
    state: SessionState,
    /// Current protocol classification hint.
    protocol: ProtocolHint,
    /// Current processing mode.
    mode: ProcessingMode,
    /// Current TLS policy.
    tls_policy: TlsPolicy,
    /// Current application protocol.
    application_protocol: ApplicationProtocol,
    /// Tags derived from the current strong session state.
    tags: TagSet,
    /// Recorded close reason, if the session has closed.
    close_reason: Option<CloseReason>,
}

impl Session {
    /// Creates a session with default connection-level processing state.
    #[must_use]
    pub fn new(
        id: SessionId,
        client_addr: SocketAddr,
        target: TargetAddr,
        source: IngressSource,
    ) -> Self {
        let mut session = Self {
            id,
            client_addr,
            target,
            source,
            state: SessionState::Socks5Connected,
            protocol: ProtocolHint::Unknown,
            mode: ProcessingMode::Inspect,
            tls_policy: TlsPolicy::Undecided,
            application_protocol: ApplicationProtocol::Unknown,
            tags: TagSet::new(),
            close_reason: None,
        };
        session.refresh_tags();
        session
    }

    /// Returns the current session state.
    #[must_use]
    pub const fn state(&self) -> SessionState {
        self.state
    }

    /// Returns the current protocol classification hint.
    #[must_use]
    pub const fn protocol(&self) -> ProtocolHint {
        self.protocol
    }

    /// Returns the current processing mode.
    #[must_use]
    pub const fn mode(&self) -> ProcessingMode {
        self.mode
    }

    /// Returns the current TLS policy.
    #[must_use]
    pub const fn tls_policy(&self) -> TlsPolicy {
        self.tls_policy
    }

    /// Returns the current application protocol.
    #[must_use]
    pub const fn application_protocol(&self) -> ApplicationProtocol {
        self.application_protocol
    }

    /// Returns tags derived from the current strong session state.
    #[must_use]
    pub const fn tags(&self) -> &TagSet {
        &self.tags
    }

    /// Returns the recorded close reason, if the session has closed.
    #[must_use]
    pub const fn close_reason(&self) -> Option<CloseReason> {
        self.close_reason
    }

    /// Sets the current session state.
    pub fn set_state(&mut self, state: SessionState) {
        self.state = state;
        self.refresh_tags();
    }

    /// Sets the current protocol classification hint.
    pub fn set_protocol(&mut self, protocol: ProtocolHint) {
        self.protocol = protocol;
        self.refresh_tags();
    }

    /// Sets the current processing mode.
    pub fn set_mode(&mut self, mode: ProcessingMode) {
        self.mode = mode;
        self.refresh_tags();
    }

    /// Sets the current TLS policy.
    pub fn set_tls_policy(&mut self, tls_policy: TlsPolicy) {
        self.tls_policy = tls_policy;
        self.refresh_tags();
    }

    /// Sets the current application protocol.
    pub fn set_application_protocol(&mut self, application_protocol: ApplicationProtocol) {
        self.application_protocol = application_protocol;
        self.refresh_tags();
    }

    /// Closes the session and records the close reason.
    pub fn close(&mut self, reason: CloseReason) {
        self.state = SessionState::Closed;
        self.mode = ProcessingMode::Closed;
        self.close_reason = Some(reason);
        self.refresh_tags();
    }

    fn refresh_tags(&mut self) {
        self.tags = derive_session_tags(
            self.state,
            self.mode,
            self.protocol,
            self.tls_policy,
            self.application_protocol,
        );
    }
}

/// HTTP request and response exchange associated with a session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transaction {
    /// Transaction identifier.
    pub id: TransactionId,
    /// Parent session identifier.
    pub session_id: SessionId,
    /// Current transaction state.
    pub state: TransactionState,
}

impl Transaction {
    /// Creates a transaction in the request-reading state.
    #[must_use]
    pub const fn new(id: TransactionId, session_id: SessionId) -> Self {
        Self {
            id,
            session_id,
            state: TransactionState::RequestReading,
        }
    }
}

/// Display and storage index for a session or transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Flow {
    /// Flow identifier.
    pub id: FlowId,
    /// Parent session identifier.
    pub session_id: SessionId,
    /// Associated transaction identifier for transaction-level flows.
    pub transaction_id: Option<TransactionId>,
    /// Protocol hint attached to the flow.
    pub protocol: ProtocolHint,
}

impl Flow {
    /// Creates a flow associated with an entire session.
    #[must_use]
    pub const fn for_session(id: FlowId, session_id: SessionId, protocol: ProtocolHint) -> Self {
        Self {
            id,
            session_id,
            transaction_id: None,
            protocol,
        }
    }

    /// Creates a flow associated with a single transaction.
    #[must_use]
    pub const fn for_transaction(
        id: FlowId,
        session_id: SessionId,
        transaction_id: TransactionId,
        protocol: ProtocolHint,
    ) -> Self {
        Self {
            id,
            session_id,
            transaction_id: Some(transaction_id),
            protocol,
        }
    }
}

/// Error returned while constructing or validating session types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionError {
    /// Domain name target failed validation.
    InvalidDomain,
    /// Target port failed validation.
    InvalidPort,
}

impl fmt::Display for SessionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidDomain => "invalid domain",
            Self::InvalidPort => "invalid port",
        };
        f.write_str(message)
    }
}

impl Error for SessionError {}

const fn validate_port(port: u16) -> Result<(), SessionError> {
    if port == 0 {
        Err(SessionError::InvalidPort)
    } else {
        Ok(())
    }
}

fn validate_domain(domain: &str) -> Result<(), SessionError> {
    if domain.is_empty() || domain.len() > 255 || domain.chars().any(char::is_whitespace) {
        return Err(SessionError::InvalidDomain);
    }

    if domain
        .split('.')
        .any(|label| label.is_empty() || label.len() > 63)
    {
        return Err(SessionError::InvalidDomain);
    }

    Ok(())
}
