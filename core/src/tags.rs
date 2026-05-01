//! Tag storage, matching, and derivation rules.

use std::collections::BTreeSet;

use crate::session::{ApplicationProtocol, ProcessingMode, ProtocolHint, SessionState, TlsPolicy};

/// Derived tag collection used for lookup and display.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TagSet {
    tags: BTreeSet<String>,
}

impl TagSet {
    /// Creates an empty tag set.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Inserts a tag, replacing existing values in single-value namespaces.
    pub fn insert(&mut self, tag: impl Into<String>) {
        let tag = tag.into();
        if let Some(namespace) = single_value_namespace(&tag) {
            let prefix = format!("{namespace}:");
            self.tags.retain(|existing| !existing.starts_with(&prefix));
        }
        self.tags.insert(tag);
    }

    /// Returns whether the tag set contains `tag`.
    #[must_use]
    pub fn contains(&self, tag: &str) -> bool {
        self.tags.contains(tag)
    }

    /// Returns all tags in deterministic order.
    pub fn iter(&self) -> impl Iterator<Item = &str> {
        self.tags.iter().map(String::as_str)
    }
}

/// Derives session tags from strong state fields.
#[must_use]
pub fn derive_session_tags(
    state: SessionState,
    mode: ProcessingMode,
    protocol: ProtocolHint,
    tls_policy: TlsPolicy,
    application_protocol: ApplicationProtocol,
) -> TagSet {
    let mut tags = TagSet::new();

    tags.insert(state_tag(state));
    tags.insert(mode_tag(mode));
    tags.insert(protocol_tag(protocol, application_protocol));
    tags.insert(transport_tag(protocol));
    tags.insert(tls_policy_tag(tls_policy));

    tags
}

fn single_value_namespace(tag: &str) -> Option<&str> {
    let namespace = tag.split_once(':')?.0;
    match namespace {
        "mode" | "proto" | "transport" | "state" | "upstream" | "body" => Some(namespace),
        _ => None,
    }
}

const fn state_tag(state: SessionState) -> &'static str {
    match state {
        SessionState::Socks5Connected => "state:socks5_connected",
        SessionState::Socks5Negotiated => "state:socks5_negotiated",
        SessionState::ConnectAccepted => "state:connect_accepted",
        SessionState::Classifying => "state:classifying",
        SessionState::InspectingHttp => "state:inspecting_http",
        SessionState::RawTunneling => "state:raw_tunneling",
        SessionState::Closing => "state:closing",
        SessionState::Closed => "state:closed",
    }
}

const fn mode_tag(mode: ProcessingMode) -> &'static str {
    match mode {
        ProcessingMode::Inspect => "mode:inspect",
        ProcessingMode::RawTunnel => "mode:raw_tunnel",
        ProcessingMode::Closed => "mode:closed",
    }
}

const fn protocol_tag(
    protocol: ProtocolHint,
    application_protocol: ApplicationProtocol,
) -> &'static str {
    match protocol {
        ProtocolHint::RawTcp => "proto:raw_tcp",
        ProtocolHint::H2c => "proto:h2c",
        ProtocolHint::Http1 => "proto:http1",
        ProtocolHint::Tls => match application_protocol {
            ApplicationProtocol::Http1 => "proto:http1",
            ApplicationProtocol::H2 => "proto:h2",
            ApplicationProtocol::Other => "proto:other",
            ApplicationProtocol::Unknown => "proto:tls",
        },
        ProtocolHint::Unknown => match application_protocol {
            ApplicationProtocol::Http1 => "proto:http1",
            ApplicationProtocol::H2 => "proto:h2",
            ApplicationProtocol::Other => "proto:other",
            ApplicationProtocol::Unknown => "proto:unknown",
        },
    }
}

const fn transport_tag(protocol: ProtocolHint) -> &'static str {
    match protocol {
        ProtocolHint::Tls => "transport:tls",
        ProtocolHint::Unknown | ProtocolHint::RawTcp | ProtocolHint::Http1 | ProtocolHint::H2c => {
            "transport:tcp"
        }
    }
}

const fn tls_policy_tag(tls_policy: TlsPolicy) -> &'static str {
    match tls_policy {
        TlsPolicy::Undecided => "tls:undecided",
        TlsPolicy::Mitm => "tls:mitm",
        TlsPolicy::Bypass => "tls:bypass",
    }
}
