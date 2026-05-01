//! Replay buffer behavior tests.

use std::{
    cell::Cell,
    io::{self, Cursor, Read, Write},
    rc::Rc,
};

use mitm_core::{
    classify::{
        classify_protocol_prefix, read_until_classified, ClassifierReadResult, PeekBuffer,
        ProtocolClassification, ReplayStream, H2C_PRIOR_KNOWLEDGE,
    },
    session::ProtocolHint,
};

#[test]
fn replay_stream_replays_prefix_before_underlying_stream() {
    let stream = Cursor::new(b"world".to_vec());
    let mut replay = ReplayStream::new(b"hello ".to_vec(), stream);
    let mut output = String::new();

    replay.read_to_string(&mut output).unwrap();

    assert_eq!(output, "hello world");
}

#[test]
fn replay_stream_supports_segmented_reads_across_prefix_boundary() {
    let stream = Cursor::new(b"defghi".to_vec());
    let mut replay = ReplayStream::new(b"abc".to_vec(), stream);
    let mut buf = [0_u8; 2];

    let first = replay.read(&mut buf).unwrap();
    assert_eq!(first, 2);
    assert_eq!(&buf, b"ab");

    let second = replay.read(&mut buf).unwrap();
    assert_eq!(second, 1);
    assert_eq!(&buf[..second], b"c");

    let third = replay.read(&mut buf).unwrap();
    assert_eq!(third, 2);
    assert_eq!(&buf, b"de");

    let fourth = replay.read(&mut buf).unwrap();
    assert_eq!(fourth, 2);
    assert_eq!(&buf, b"fg");

    let fifth = replay.read(&mut buf).unwrap();
    assert_eq!(fifth, 2);
    assert_eq!(&buf, b"hi");

    let eof = replay.read(&mut buf).unwrap();
    assert_eq!(eof, 0);
}

#[test]
fn replay_stream_does_not_read_inner_until_prefix_is_exhausted_at_call_start() {
    let inner = CountingReader::new(b"tail".to_vec());
    let calls = inner.calls();
    let mut replay = ReplayStream::new(b"head".to_vec(), inner);
    let mut first = [0_u8; 8];
    let mut second = [0_u8; 8];

    let first_len = replay.read(&mut first).unwrap();
    assert_eq!(first_len, 4);
    assert_eq!(&first[..first_len], b"head");
    assert_eq!(calls.get(), 0);

    let second_len = replay.read(&mut second).unwrap();
    assert_eq!(second_len, 4);
    assert_eq!(&second[..second_len], b"tail");
    assert_eq!(calls.get(), 1);
}

#[test]
fn replay_stream_consumes_prefix_once() {
    let stream = Cursor::new(b"tail".to_vec());
    let mut replay = ReplayStream::new(b"head".to_vec(), stream);
    let mut first = [0_u8; 4];
    let mut second = [0_u8; 4];
    let mut third = [0_u8; 4];

    assert_eq!(replay.read(&mut first).unwrap(), 4);
    assert_eq!(&first, b"head");
    assert_eq!(replay.read(&mut second).unwrap(), 4);
    assert_eq!(&second, b"tail");
    assert_eq!(replay.read(&mut third).unwrap(), 0);
}

#[test]
fn replay_stream_delegates_write_to_inner_stream() {
    let stream = Cursor::new(Vec::new());
    let mut replay = ReplayStream::new(b"prefix".to_vec(), stream);

    replay.write_all(b"tail").unwrap();
    replay.flush().unwrap();

    let mut prefix = [0_u8; 6];
    replay.read_exact(&mut prefix).unwrap();
    assert_eq!(&prefix, b"prefix");

    let inner = replay
        .try_into_inner()
        .expect("prefix has been fully consumed");
    assert_eq!(inner.into_inner(), b"tail".to_vec());
}

#[test]
fn replay_stream_try_into_inner_requires_consumed_prefix() {
    let stream = Cursor::new(b"tail".to_vec());
    let replay = ReplayStream::new(b"head".to_vec(), stream);

    let replay = replay
        .try_into_inner()
        .expect_err("prefix bytes remain available");
    let mut replay = replay;
    let mut prefix = [0_u8; 4];
    assert_eq!(replay.read(&mut prefix).unwrap(), 4);
    assert_eq!(&prefix, b"head");

    let mut tail = [0_u8; 4];
    assert_eq!(replay.read(&mut tail).unwrap(), 4);
    assert_eq!(&tail, b"tail");

    let inner = replay
        .try_into_inner()
        .expect("prefix has been fully consumed");
    assert_eq!(inner.into_inner(), b"tail".to_vec());
}

#[test]
fn peek_buffer_from_vec_uses_existing_prefix() {
    let peek = PeekBuffer::from_vec(b"cached".to_vec());

    assert_eq!(peek.as_slice(), b"cached");
    assert_eq!(peek.len(), 6);
}

#[test]
fn peek_buffer_reads_prefix_without_losing_order() {
    let mut source = Cursor::new(b"abcdef".to_vec());
    let mut peek = PeekBuffer::new();

    let first = peek.read_more(&mut source, 2).unwrap();
    assert_eq!(first, 2);
    assert_eq!(peek.as_slice(), b"ab");

    let second = peek.read_more(&mut source, 3).unwrap();
    assert_eq!(second, 3);
    assert_eq!(peek.as_slice(), b"abcde");

    let mut replay = peek.into_replay_stream(source);
    let mut output = Vec::new();
    replay.read_to_end(&mut output).unwrap();

    assert_eq!(output, b"abcdef");
}

#[test]
fn peek_buffer_into_vec_transfers_buffer_ownership() {
    let mut source = Cursor::new(b"abcdef".to_vec());
    let mut peek = PeekBuffer::new();

    peek.read_more(&mut source, 3).unwrap();

    assert_eq!(peek.into_vec(), b"abc".to_vec());
}

#[test]
fn peek_buffer_read_more_performs_one_underlying_read() {
    let mut source = CountingReader::new(b"abcdef".to_vec()).with_max_chunk(2);
    let calls = source.calls();
    let mut peek = PeekBuffer::new();

    let read = peek.read_more(&mut source, 4).unwrap();

    assert_eq!(read, 2);
    assert_eq!(peek.as_slice(), b"ab");
    assert_eq!(calls.get(), 1);
}

#[test]
fn classify_protocol_prefix_detects_http1_methods() {
    for prefix in [
        b"GET / HTTP/1.1\r\n".as_slice(),
        b"POST /items HTTP/1.1\r\n".as_slice(),
        b"PUT /items/1 HTTP/1.1\r\n".as_slice(),
        b"DELETE /items/1 HTTP/1.1\r\n".as_slice(),
        b"PATCH /items/1 HTTP/1.1\r\n".as_slice(),
        b"HEAD / HTTP/1.1\r\n".as_slice(),
        b"OPTIONS * HTTP/1.1\r\n".as_slice(),
    ] {
        assert_eq!(
            classify_protocol_prefix(prefix),
            ProtocolClassification::Complete(ProtocolHint::Http1)
        );
    }
}

#[test]
fn classify_protocol_prefix_detects_tls_client_hello() {
    let prefix = [0x16, 0x03, 0x01, 0x00, 0x2e, 0x01, 0x00, 0x00];

    assert_eq!(
        classify_protocol_prefix(&prefix),
        ProtocolClassification::Complete(ProtocolHint::Tls)
    );
}

#[test]
fn classify_protocol_prefix_detects_h2c_prior_knowledge() {
    assert_eq!(
        classify_protocol_prefix(H2C_PRIOR_KNOWLEDGE),
        ProtocolClassification::Complete(ProtocolHint::H2c)
    );
}

#[test]
fn classify_protocol_prefix_defaults_to_raw_tcp() {
    assert_eq!(
        classify_protocol_prefix(b"SSH-2.0-openssh\r\n"),
        ProtocolClassification::Complete(ProtocolHint::RawTcp)
    );
}

#[test]
fn classify_protocol_prefix_reports_need_more_for_short_prefixes() {
    for prefix in [
        b"".as_slice(),
        b"G".as_slice(),
        b"PO".as_slice(),
        b"PRI * HTTP".as_slice(),
        &[0x16],
        &[0x16, 0x03, 0x03, 0x00, 0x2e],
    ] {
        assert_eq!(
            classify_protocol_prefix(prefix),
            ProtocolClassification::NeedMore
        );
    }
}

#[test]
fn read_until_classified_reports_waitable_need_more_without_reading() {
    let mut peek = PeekBuffer::from_vec(b"G".to_vec());
    let mut source = Cursor::new(b"ET / HTTP/1.1\r\n".to_vec());

    assert_eq!(
        read_until_classified(&mut peek, &mut source, 0),
        ClassifierReadResult::NeedMore
    );
    assert_eq!(peek.as_slice(), b"G");
}

#[test]
fn read_until_classified_distinguishes_complete_eof_and_limit_exhausted() {
    let mut complete_peek = PeekBuffer::new();
    let mut complete_source = Cursor::new(b"GET / HTTP/1.1\r\n".to_vec());

    assert_eq!(
        read_until_classified(&mut complete_peek, &mut complete_source, 24),
        ClassifierReadResult::Complete(ProtocolHint::Http1)
    );

    let mut eof_peek = PeekBuffer::from_vec(b"G".to_vec());
    let mut eof_source = Cursor::new(Vec::new());

    assert_eq!(
        read_until_classified(&mut eof_peek, &mut eof_source, 24),
        ClassifierReadResult::IncompleteEof
    );

    let mut limit_peek = PeekBuffer::from_vec(b"PRI * HTTP".to_vec());
    let mut limit_source = Cursor::new(b"/2".to_vec());
    let limit = limit_peek.len() + 2;

    assert_eq!(
        read_until_classified(&mut limit_peek, &mut limit_source, limit),
        ClassifierReadResult::LimitExhausted
    );
}

#[test]
fn read_until_classified_reports_io_error() {
    let mut peek = PeekBuffer::from_vec(b"G".to_vec());
    let mut source = FailingReader;

    assert_eq!(
        read_until_classified(&mut peek, &mut source, 24),
        ClassifierReadResult::IoError
    );
}

struct CountingReader {
    data: Cursor<Vec<u8>>,
    calls: Rc<Cell<usize>>,
    max_chunk: Option<usize>,
}

impl CountingReader {
    fn new(data: Vec<u8>) -> Self {
        Self {
            data: Cursor::new(data),
            calls: Rc::new(Cell::new(0)),
            max_chunk: None,
        }
    }

    fn calls(&self) -> Rc<Cell<usize>> {
        Rc::clone(&self.calls)
    }

    fn with_max_chunk(mut self, max_chunk: usize) -> Self {
        self.max_chunk = Some(max_chunk);
        self
    }
}

impl Read for CountingReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.calls.set(self.calls.get() + 1);
        let limit = self.max_chunk.unwrap_or(buf.len()).min(buf.len());
        self.data.read(&mut buf[..limit])
    }
}

struct FailingReader;

impl Read for FailingReader {
    fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::other("read failed"))
    }
}
