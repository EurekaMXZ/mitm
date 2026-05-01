//! TCP byte classification and protocol hint primitives.

#![allow(clippy::module_name_repetitions)]

use std::io::{self, Read, Write};

use crate::{
    handler::{Handler, HandlerContext, HandlerOutcome, HandlerResult, StreamSlot},
    session::{CloseReason, ProcessingMode, ProtocolHint, SessionState},
};

/// HTTP/2 cleartext prior-knowledge connection preface.
pub const H2C_PRIOR_KNOWLEDGE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

const HTTP1_METHOD_PREFIXES: &[&[u8]] = &[
    b"GET ",
    b"POST ",
    b"PUT ",
    b"DELETE ",
    b"PATCH ",
    b"HEAD ",
    b"OPTIONS ",
];

const DEFAULT_CLASSIFIER_READ_LIMIT: usize = H2C_PRIOR_KNOWLEDGE.len();

/// Result of classifying a downstream byte prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolClassification {
    /// More downstream bytes are required before a protocol can be selected.
    NeedMore,
    /// The prefix is sufficient to select a protocol hint.
    Complete(ProtocolHint),
}

/// Result of reading downstream bytes until classification can make progress.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClassifierReadResult {
    /// A protocol hint was selected.
    Complete(ProtocolHint),
    /// More bytes are required and the stream may produce them later.
    NeedMore,
    /// The downstream side reached EOF before classification completed.
    IncompleteEof,
    /// The downstream read returned an I/O error.
    IoError,
    /// The configured read limit was exhausted before classification completed.
    LimitExhausted,
}

/// Classifies a buffered downstream prefix into a protocol classification result.
#[must_use]
pub fn classify_protocol_prefix(prefix: &[u8]) -> ProtocolClassification {
    if is_http1_prefix(prefix) {
        ProtocolClassification::Complete(ProtocolHint::Http1)
    } else if is_tls_client_hello_prefix(prefix) {
        ProtocolClassification::Complete(ProtocolHint::Tls)
    } else if prefix.starts_with(H2C_PRIOR_KNOWLEDGE) {
        ProtocolClassification::Complete(ProtocolHint::H2c)
    } else if needs_more_prefix_bytes(prefix) {
        ProtocolClassification::NeedMore
    } else {
        ProtocolClassification::Complete(ProtocolHint::RawTcp)
    }
}

fn is_http1_prefix(prefix: &[u8]) -> bool {
    HTTP1_METHOD_PREFIXES
        .iter()
        .any(|method| prefix.starts_with(method))
}

fn is_tls_client_hello_prefix(prefix: &[u8]) -> bool {
    prefix.len() >= 6
        && prefix[0] == 0x16
        && prefix[1] == 0x03
        && matches!(prefix[2], 0x00..=0x04)
        && prefix[5] == 0x01
}

fn needs_more_prefix_bytes(prefix: &[u8]) -> bool {
    prefix.is_empty()
        || HTTP1_METHOD_PREFIXES
            .iter()
            .any(|method| method.starts_with(prefix))
        || H2C_PRIOR_KNOWLEDGE.starts_with(prefix)
        || could_be_tls_client_hello_prefix(prefix)
}

fn could_be_tls_client_hello_prefix(prefix: &[u8]) -> bool {
    match prefix {
        [] | [0x16] | [0x16, 0x03] | [0x16, 0x03, 0x00..=0x04] => true,
        [0x16, 0x03, minor, ..] if prefix.len() < 6 && matches!(minor, 0x00..=0x04) => true,
        _ => false,
    }
}

/// Handler that records the protocol classification result and buffered prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProtocolClassifierHandler;

impl ProtocolClassifierHandler {
    /// Creates a classifier handler that reads from [`HandlerContext::stream`].
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl Default for ProtocolClassifierHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl Handler for ProtocolClassifierHandler {
    fn name(&self) -> &'static str {
        "protocol-classifier"
    }

    fn handle(&self, ctx: &mut HandlerContext) -> HandlerOutcome {
        let slot = ctx.stream.take();
        let (prefix, mut stream) = match slot.into_replay_parts() {
            Ok(parts) => parts,
            Err(slot) => {
                ctx.stream = slot;
                return HandlerOutcome {
                    decision: None,
                    control: HandlerResult::Continue,
                };
            }
        };

        let mut peek = PeekBuffer::from_vec(prefix);
        let read_result =
            read_until_classified(&mut peek, &mut stream, DEFAULT_CLASSIFIER_READ_LIMIT);

        match read_result {
            ClassifierReadResult::Complete(protocol) => {
                apply_protocol_hint(ctx, protocol);
                ctx.stream = StreamSlot::Peeked {
                    prefix: peek.into_vec(),
                    stream,
                };

                HandlerOutcome {
                    decision: None,
                    control: HandlerResult::Continue,
                }
            }
            ClassifierReadResult::NeedMore => {
                ctx.session.set_state(SessionState::Classifying);
                ctx.stream = StreamSlot::Peeked {
                    prefix: peek.into_vec(),
                    stream,
                };

                HandlerOutcome {
                    decision: None,
                    control: HandlerResult::Stop,
                }
            }
            ClassifierReadResult::IncompleteEof | ClassifierReadResult::LimitExhausted => {
                close_unclassified_session(ctx, CloseReason::ProtocolError)
            }
            ClassifierReadResult::IoError => {
                close_unclassified_session(ctx, CloseReason::InternalError)
            }
        }
    }
}

/// Reads bytes until classification completes, more bytes are needed, or reading fails.
pub fn read_until_classified(
    peek: &mut PeekBuffer,
    stream: &mut impl Read,
    limit: usize,
) -> ClassifierReadResult {
    loop {
        let classification = classify_protocol_prefix(peek.as_slice());
        if let ProtocolClassification::Complete(protocol) = classification {
            return ClassifierReadResult::Complete(protocol);
        }

        let remaining_limit = limit.saturating_sub(peek.len());
        if remaining_limit == 0 {
            return if limit == 0 {
                ClassifierReadResult::NeedMore
            } else {
                ClassifierReadResult::LimitExhausted
            };
        }

        match peek.read_more(stream, remaining_limit) {
            Ok(0) => return ClassifierReadResult::IncompleteEof,
            Ok(_) => {}
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                return ClassifierReadResult::NeedMore;
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => return ClassifierReadResult::IoError,
        }
    }
}

fn close_unclassified_session(ctx: &mut HandlerContext, reason: CloseReason) -> HandlerOutcome {
    ctx.session.close(reason);
    ctx.stream = StreamSlot::Closed;

    HandlerOutcome {
        decision: None,
        control: HandlerResult::Stop,
    }
}

fn apply_protocol_hint(ctx: &mut HandlerContext, protocol: ProtocolHint) {
    ctx.session.set_protocol(protocol);

    match protocol {
        ProtocolHint::Http1 => {
            ctx.session.set_mode(ProcessingMode::Inspect);
            ctx.session.set_state(SessionState::InspectingHttp);
        }
        ProtocolHint::Tls => {
            ctx.session.set_state(SessionState::Classifying);
        }
        ProtocolHint::H2c | ProtocolHint::RawTcp => {
            ctx.session.set_mode(ProcessingMode::RawTunnel);
            ctx.session.set_state(SessionState::RawTunneling);
        }
        ProtocolHint::Unknown => {}
    }
}

/// Buffered bytes read from a downstream stream during protocol classification.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PeekBuffer {
    bytes: Vec<u8>,
}

impl PeekBuffer {
    /// Creates an empty peek buffer.
    #[must_use]
    pub const fn new() -> Self {
        Self { bytes: Vec::new() }
    }

    /// Creates a peek buffer from existing prefix bytes.
    #[must_use]
    pub const fn from_vec(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    /// Returns the buffered prefix bytes.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes
    }

    /// Transfers ownership of the buffered prefix bytes.
    #[must_use]
    pub fn into_vec(self) -> Vec<u8> {
        self.bytes
    }

    /// Returns the number of buffered prefix bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Returns whether the buffer contains no prefix bytes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Reads up to `limit` additional bytes and appends them to the prefix.
    ///
    /// # Errors
    ///
    /// Returns any I/O error reported by the wrapped reader.
    pub fn read_more<R>(&mut self, reader: &mut R, limit: usize) -> io::Result<usize>
    where
        R: Read,
    {
        if limit == 0 {
            return Ok(0);
        }

        let mut buf = vec![0_u8; limit];
        let read = reader.read(&mut buf)?;
        self.bytes.extend_from_slice(&buf[..read]);
        Ok(read)
    }

    /// Creates a replay stream that emits the buffered prefix before `stream`.
    #[must_use]
    pub fn into_replay_stream<R>(self, stream: R) -> ReplayStream<R>
    where
        R: Read,
    {
        ReplayStream::new(self.bytes, stream)
    }
}

/// Read wrapper that replays buffered prefix bytes before reading the inner stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayStream<R> {
    prefix: Vec<u8>,
    position: usize,
    inner: R,
}

impl<R> ReplayStream<R>
where
    R: Read,
{
    /// Creates a replay stream from prefix bytes and an underlying reader.
    #[must_use]
    pub const fn new(prefix: Vec<u8>, inner: R) -> Self {
        Self {
            prefix,
            position: 0,
            inner,
        }
    }

    /// Returns the wrapped reader when all prefix bytes have been consumed.
    ///
    /// # Errors
    ///
    /// Returns the original replay stream when prefix bytes remain available.
    pub fn try_into_inner(self) -> Result<R, Self> {
        if self.position == self.prefix.len() {
            Ok(self.inner)
        } else {
            Err(self)
        }
    }

    /// Returns prefix bytes that have not been consumed yet.
    #[must_use]
    pub fn remaining_prefix(&self) -> &[u8] {
        &self.prefix[self.position..]
    }
}

impl<R> Read for ReplayStream<R>
where
    R: Read,
{
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        let remaining_prefix = self.remaining_prefix();
        if remaining_prefix.is_empty() {
            return self.inner.read(buf);
        }

        let replayed = remaining_prefix.len().min(buf.len());
        buf[..replayed].copy_from_slice(&remaining_prefix[..replayed]);
        self.position += replayed;

        Ok(replayed)
    }
}

impl<R> Write for ReplayStream<R>
where
    R: Write,
{
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}
