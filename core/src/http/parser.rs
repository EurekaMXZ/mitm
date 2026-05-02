//! HTTP request and response parser primitives plus buffered serializers.

use std::fmt;
use std::io::{self, ErrorKind, Read, Write};

use super::{
    body::{
        determine_request_body_framing, determine_response_body_framing, read_buffered_body,
        write_body,
    },
    HttpRequestView, HttpResponseView, HttpVersion, RawHeader,
};

/// Result of attempting to read the next HTTP request from a byte stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestReadOutcome {
    /// Reader was already at EOF before any request bytes were consumed.
    CleanEof,
    /// A complete request was parsed and its buffered body was read.
    Request(HttpRequestView),
}

/// Errors produced while parsing HTTP message heads or buffered bodies.
#[derive(Debug)]
pub enum HttpError {
    /// Underlying I/O failure.
    Io(io::Error),
    /// Stream ended before a complete message could be read.
    UnexpectedEof,
    /// Request line is missing or malformed.
    InvalidRequestLine,
    /// Status line is missing or malformed.
    InvalidStatusLine,
    /// HTTP version token is unsupported.
    UnsupportedHttpVersion,
    /// Header line is malformed.
    InvalidHeaderLine,
    /// Header bytes are not valid UTF-8.
    InvalidHeaderEncoding,
    /// `Content-Length` is missing digits or cannot be parsed.
    InvalidContentLength,
    /// Multiple `Content-Length` values disagree.
    ConflictingContentLength,
    /// `Transfer-Encoding` value list is malformed.
    InvalidTransferEncoding,
    /// Transfer coding other than terminal `chunked` is present.
    UnsupportedTransferEncoding,
    /// Chunk size line is malformed.
    InvalidChunkSize,
    /// Chunk data is not followed by `\r\n`.
    InvalidChunkTerminator,
}

impl fmt::Display for HttpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "i/o error: {error}"),
            Self::UnexpectedEof => f.write_str("unexpected eof while reading http message"),
            Self::InvalidRequestLine => f.write_str("invalid http request line"),
            Self::InvalidStatusLine => f.write_str("invalid http status line"),
            Self::UnsupportedHttpVersion => f.write_str("unsupported http version"),
            Self::InvalidHeaderLine => f.write_str("invalid http header line"),
            Self::InvalidHeaderEncoding => f.write_str("invalid http header encoding"),
            Self::InvalidContentLength => f.write_str("invalid content-length header"),
            Self::ConflictingContentLength => f.write_str("conflicting content-length headers"),
            Self::InvalidTransferEncoding => f.write_str("invalid transfer-encoding header"),
            Self::UnsupportedTransferEncoding => f.write_str("unsupported transfer-encoding"),
            Self::InvalidChunkSize => f.write_str("invalid chunk size"),
            Self::InvalidChunkTerminator => f.write_str("invalid chunk terminator"),
        }
    }
}

impl std::error::Error for HttpError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for HttpError {
    fn from(error: io::Error) -> Self {
        if error.kind() == ErrorKind::UnexpectedEof {
            Self::UnexpectedEof
        } else {
            Self::Io(error)
        }
    }
}

/// Reads one HTTP request with a fully buffered body according to framing headers.
///
/// # Errors
///
/// Returns [`HttpError`] when the request line, headers, framing metadata, or
/// buffered body bytes are malformed or cannot be read from `reader`.
pub fn read_http_request<R: Read>(reader: &mut R) -> Result<RequestReadOutcome, HttpError> {
    let Some(request_line) = read_crlf_line(reader)? else {
        return Ok(RequestReadOutcome::CleanEof);
    };

    if request_line.is_empty() {
        return Err(HttpError::InvalidRequestLine);
    }

    let (method, target, version) = parse_request_line(&request_line)?;
    let headers = read_header_block(reader)?;
    let body_framing = determine_request_body_framing(&headers)?;
    let body = read_buffered_body(reader, &body_framing)?;

    Ok(RequestReadOutcome::Request(HttpRequestView::new(
        method,
        target,
        version,
        headers,
        body,
        body_framing,
    )))
}

/// Reads one HTTP response with a fully buffered body according to framing headers.
///
/// # Errors
///
/// Returns [`HttpError`] when the status line, headers, framing metadata, or
/// buffered body bytes are malformed or cannot be read from `reader`.
pub fn read_http_response<R: Read>(
    reader: &mut R,
    request_method: &str,
) -> Result<HttpResponseView, HttpError> {
    let status_line = read_crlf_line(reader)?.ok_or(HttpError::UnexpectedEof)?;
    if status_line.is_empty() {
        return Err(HttpError::InvalidStatusLine);
    }

    let (version, status, reason_phrase) = parse_status_line(&status_line)?;
    let headers = read_header_block(reader)?;
    let body_framing = determine_response_body_framing(request_method, status, &headers)?;
    let body = read_buffered_body(reader, &body_framing)?;

    Ok(HttpResponseView::new(
        version,
        status,
        reason_phrase,
        headers,
        body,
        body_framing,
    ))
}

/// Serializes a buffered HTTP request while preserving header order and casing.
///
/// # Errors
///
/// Returns any I/O error from `writer`.
pub fn write_http_request<W: Write>(writer: &mut W, request: &HttpRequestView) -> io::Result<()> {
    write!(
        writer,
        "{} {} {}\r\n",
        request.method, request.target, request.version
    )?;
    write_header_block(writer, request.headers())?;
    write_body(writer, &request.body_framing, &request.body)
}

/// Serializes a buffered HTTP response while preserving header order and casing.
///
/// # Errors
///
/// Returns any I/O error from `writer`.
pub fn write_http_response<W: Write>(
    writer: &mut W,
    response: &HttpResponseView,
) -> io::Result<()> {
    write!(
        writer,
        "{} {} {}\r\n",
        response.version, response.status, response.reason_phrase
    )?;
    write_header_block(writer, response.headers())?;
    write_body(writer, &response.body_framing, &response.body)
}

pub(crate) fn read_crlf_line<R: Read>(reader: &mut R) -> Result<Option<Vec<u8>>, HttpError> {
    let mut line = Vec::new();
    let mut byte = [0_u8; 1];

    loop {
        match reader.read(&mut byte) {
            Ok(0) if line.is_empty() => return Ok(None),
            Ok(0) => return Err(HttpError::UnexpectedEof),
            Ok(_) => {
                line.push(byte[0]);
                if line.len() >= 2 && line[line.len() - 2..] == *b"\r\n" {
                    line.truncate(line.len() - 2);
                    return Ok(Some(line));
                }
            }
            Err(error) if error.kind() == ErrorKind::Interrupted => {}
            Err(error) => return Err(HttpError::from(error)),
        }
    }
}

pub(crate) fn read_line_string(line: Vec<u8>, context: &'static str) -> Result<String, HttpError> {
    String::from_utf8(line).map_err(|_| match context {
        "request line" => HttpError::InvalidRequestLine,
        "status line" => HttpError::InvalidStatusLine,
        "chunk size" => HttpError::InvalidChunkSize,
        _ => HttpError::InvalidHeaderEncoding,
    })
}

fn parse_request_line(line: &[u8]) -> Result<(String, String, HttpVersion), HttpError> {
    let line = read_line_string(line.to_vec(), "request line")?;
    let mut parts = line.split_whitespace();

    let method = parts.next().ok_or(HttpError::InvalidRequestLine)?;
    let target = parts.next().ok_or(HttpError::InvalidRequestLine)?;
    let version = parts.next().ok_or(HttpError::InvalidRequestLine)?;

    if parts.next().is_some() {
        return Err(HttpError::InvalidRequestLine);
    }

    Ok((
        method.to_owned(),
        target.to_owned(),
        parse_http_version(version)?,
    ))
}

fn parse_http_version(version: &str) -> Result<HttpVersion, HttpError> {
    match version {
        "HTTP/1.0" => Ok(HttpVersion::Http10),
        "HTTP/1.1" => Ok(HttpVersion::Http11),
        _ => Err(HttpError::UnsupportedHttpVersion),
    }
}

fn parse_status_line(line: &[u8]) -> Result<(HttpVersion, u16, String), HttpError> {
    let line = read_line_string(line.to_vec(), "status line")?;
    let mut parts = line.splitn(3, ' ');

    let version = parts.next().ok_or(HttpError::InvalidStatusLine)?;
    let status = parts.next().ok_or(HttpError::InvalidStatusLine)?;
    let reason_phrase = parts.next().ok_or(HttpError::InvalidStatusLine)?;

    if version.is_empty() || status.is_empty() {
        return Err(HttpError::InvalidStatusLine);
    }

    let status = status
        .parse::<u16>()
        .map_err(|_| HttpError::InvalidStatusLine)?;

    Ok((
        parse_http_version(version)?,
        status,
        reason_phrase.to_owned(),
    ))
}

fn read_header_block<R: Read>(reader: &mut R) -> Result<Vec<RawHeader>, HttpError> {
    let mut headers = Vec::new();

    loop {
        let line = read_crlf_line(reader)?.ok_or(HttpError::UnexpectedEof)?;
        if line.is_empty() {
            return Ok(headers);
        }

        headers.push(parse_header_line(line)?);
    }
}

fn parse_header_line(line: Vec<u8>) -> Result<RawHeader, HttpError> {
    let line = read_line_string(line, "header")?;
    let (name, value) = line.split_once(':').ok_or(HttpError::InvalidHeaderLine)?;
    if name.is_empty() {
        return Err(HttpError::InvalidHeaderLine);
    }

    Ok(RawHeader::new(name, value.trim_start_matches([' ', '\t'])))
}

fn write_header_block<W: Write>(writer: &mut W, headers: &[RawHeader]) -> io::Result<()> {
    for header in headers {
        write!(writer, "{}: {}\r\n", header.name, header.value)?;
    }
    writer.write_all(b"\r\n")
}
