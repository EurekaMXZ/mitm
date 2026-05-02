//! HTTP message view types with raw header fidelity.

#![allow(clippy::module_name_repetitions)]

use std::fmt;

/// HTTP version used by request and response views.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HttpVersion {
    /// HTTP/1.0.
    Http10,
    /// HTTP/1.1.
    Http11,
}

impl fmt::Display for HttpVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let version = match self {
            Self::Http10 => "HTTP/1.0",
            Self::Http11 => "HTTP/1.1",
        };
        f.write_str(version)
    }
}

/// Raw header field that preserves original name casing and insertion order.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RawHeader {
    /// Header field name with original casing.
    pub name: String,
    /// Header field value as received or serialized.
    pub value: String,
}

impl RawHeader {
    /// Creates a raw header field.
    #[must_use]
    pub fn new(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
        }
    }
}

/// HTTP body framing metadata derived from message headers and version.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum HttpBodyFraming {
    /// No message body is present.
    None,
    /// Body length is fixed by `Content-Length`.
    ContentLength(usize),
    /// Body uses HTTP chunked transfer coding.
    Chunked,
    /// Body ends when the peer closes the connection.
    ConnectionClose,
}

/// HTTP request semantic view with raw header preservation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpRequestView {
    /// Request method token.
    pub method: String,
    /// Request target as received.
    pub target: String,
    /// Parsed HTTP version.
    pub version: HttpVersion,
    /// Ordered raw request headers.
    pub headers: Vec<RawHeader>,
    /// Buffered request body bytes.
    pub body: Vec<u8>,
    /// Message framing metadata.
    pub body_framing: HttpBodyFraming,
}

impl HttpRequestView {
    /// Creates a request view.
    #[must_use]
    pub fn new(
        method: impl Into<String>,
        target: impl Into<String>,
        version: HttpVersion,
        headers: Vec<RawHeader>,
        body: Vec<u8>,
        body_framing: HttpBodyFraming,
    ) -> Self {
        Self {
            method: method.into(),
            target: target.into(),
            version,
            headers,
            body,
            body_framing,
        }
    }

    /// Returns ordered raw headers with original casing intact.
    #[must_use]
    pub fn headers(&self) -> &[RawHeader] {
        &self.headers
    }

    /// Returns header values for `name`, preserving their original order.
    #[must_use]
    pub fn header_values(&self, name: &str) -> Vec<&str> {
        header_values(&self.headers, name)
    }

    /// Returns the default keep-alive behavior implied by the HTTP version.
    #[must_use]
    pub const fn keep_alive_by_default(&self) -> bool {
        keep_alive_by_default(self.version)
    }

    /// Returns whether the request explicitly asks to close the connection.
    #[must_use]
    pub fn connection_close_requested(&self) -> bool {
        connection_close_requested(&self.headers)
    }
}

/// HTTP response semantic view with raw header preservation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpResponseView {
    /// Parsed HTTP version.
    pub version: HttpVersion,
    /// Numeric status code.
    pub status: u16,
    /// Reason phrase as received or serialized.
    pub reason_phrase: String,
    /// Ordered raw response headers.
    pub headers: Vec<RawHeader>,
    /// Buffered response body bytes.
    pub body: Vec<u8>,
    /// Message framing metadata.
    pub body_framing: HttpBodyFraming,
}

impl HttpResponseView {
    /// Creates a response view.
    #[must_use]
    pub fn new(
        version: HttpVersion,
        status: u16,
        reason_phrase: impl Into<String>,
        headers: Vec<RawHeader>,
        body: Vec<u8>,
        body_framing: HttpBodyFraming,
    ) -> Self {
        Self {
            version,
            status,
            reason_phrase: reason_phrase.into(),
            headers,
            body,
            body_framing,
        }
    }

    /// Returns ordered raw headers with original casing intact.
    #[must_use]
    pub fn headers(&self) -> &[RawHeader] {
        &self.headers
    }

    /// Returns header values for `name`, preserving their original order.
    #[must_use]
    pub fn header_values(&self, name: &str) -> Vec<&str> {
        header_values(&self.headers, name)
    }

    /// Returns the default keep-alive behavior implied by the HTTP version.
    #[must_use]
    pub const fn keep_alive_by_default(&self) -> bool {
        keep_alive_by_default(self.version)
    }

    /// Returns whether the response explicitly asks to close the connection.
    #[must_use]
    pub fn connection_close_requested(&self) -> bool {
        connection_close_requested(&self.headers)
    }
}

/// Direction-agnostic HTTP message semantic view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HttpMessageView {
    /// Request-side message view.
    Request(HttpRequestView),
    /// Response-side message view.
    Response(HttpResponseView),
}

impl HttpMessageView {
    /// Returns the default keep-alive behavior implied by the HTTP version.
    #[must_use]
    pub const fn keep_alive_by_default(&self) -> bool {
        match self {
            Self::Request(request) => request.keep_alive_by_default(),
            Self::Response(response) => response.keep_alive_by_default(),
        }
    }
}

const fn keep_alive_by_default(version: HttpVersion) -> bool {
    matches!(version, HttpVersion::Http11)
}

fn header_values<'a>(headers: &'a [RawHeader], name: &str) -> Vec<&'a str> {
    headers
        .iter()
        .filter(|header| header.name.eq_ignore_ascii_case(name))
        .map(|header| header.value.as_str())
        .collect()
}

fn connection_close_requested(headers: &[RawHeader]) -> bool {
    headers.iter().any(|header| {
        header.name.eq_ignore_ascii_case("Connection")
            && header
                .value
                .split(',')
                .any(|token| token.trim().eq_ignore_ascii_case("close"))
    })
}
