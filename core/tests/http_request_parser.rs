//! HTTP request parser behavior tests.

use std::io::Cursor;

use mitm_core::http::{
    read_http_request, HttpBodyFraming, HttpError, HttpVersion, RequestReadOutcome,
};

#[test]
fn parser_reads_get_request_without_body() {
    let mut reader =
        Cursor::new(b"GET /hello HTTP/1.1\r\nHost: example.com\r\nX-Trace: a\r\n\r\n".to_vec());

    let outcome = read_http_request(&mut reader).unwrap();
    let request = match outcome {
        RequestReadOutcome::Request(request) => request,
        other @ RequestReadOutcome::CleanEof => panic!("expected request, got {other:?}"),
    };

    assert_eq!(request.method, "GET");
    assert_eq!(request.target, "/hello");
    assert_eq!(request.version, HttpVersion::Http11);
    assert_eq!(request.body, Vec::<u8>::new());
    assert_eq!(request.body_framing, HttpBodyFraming::None);
    assert_eq!(request.headers.len(), 2);
    assert_eq!(request.headers[0].name, "Host");
    assert_eq!(request.headers[0].value, "example.com");
    assert_eq!(request.headers[1].name, "X-Trace");
    assert_eq!(request.headers[1].value, "a");
}

#[test]
fn parser_reads_content_length_request_body() {
    let mut reader = Cursor::new(
        b"POST /submit HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\n\r\nhello".to_vec(),
    );

    let outcome = read_http_request(&mut reader).unwrap();
    let request = match outcome {
        RequestReadOutcome::Request(request) => request,
        other @ RequestReadOutcome::CleanEof => panic!("expected request, got {other:?}"),
    };

    assert_eq!(request.method, "POST");
    assert_eq!(request.target, "/submit");
    assert_eq!(request.version, HttpVersion::Http11);
    assert_eq!(request.body, b"hello");
    assert_eq!(request.body_framing, HttpBodyFraming::ContentLength(5));
}

#[test]
fn parser_reads_chunked_request_body() {
    let mut reader = Cursor::new(
        b"POST /chunk HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n"
            .to_vec(),
    );

    let outcome = read_http_request(&mut reader).unwrap();
    let request = match outcome {
        RequestReadOutcome::Request(request) => request,
        other @ RequestReadOutcome::CleanEof => panic!("expected request, got {other:?}"),
    };

    assert_eq!(request.method, "POST");
    assert_eq!(request.target, "/chunk");
    assert_eq!(request.version, HttpVersion::Http11);
    assert_eq!(request.body, b"hello");
    assert_eq!(request.body_framing, HttpBodyFraming::Chunked);
}

#[test]
fn parser_rejects_transfer_encoding_gzip_then_chunked() {
    let mut reader = Cursor::new(
        b"POST /chunk HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: gzip, chunked\r\n\r\n"
            .to_vec(),
    );

    let error = read_http_request(&mut reader).unwrap_err();

    assert!(matches!(error, HttpError::UnsupportedTransferEncoding));
}

#[test]
fn parser_rejects_chunked_when_content_length_is_also_present() {
    let mut reader = Cursor::new(
        b"POST /chunk HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\nContent-Length: 5\r\n\r\n5\r\nhello\r\n0\r\n\r\n"
            .to_vec(),
    );

    let error = read_http_request(&mut reader).unwrap_err();

    assert!(matches!(error, HttpError::ConflictingContentLength));
}

#[test]
fn parser_rejects_repeated_chunked_coding_in_single_header() {
    let mut reader = Cursor::new(
        b"POST /chunk HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked, chunked\r\n\r\n"
            .to_vec(),
    );

    let error = read_http_request(&mut reader).unwrap_err();

    assert!(matches!(error, HttpError::UnsupportedTransferEncoding));
}

#[test]
fn parser_rejects_repeated_chunked_coding_across_multiple_headers() {
    let mut reader = Cursor::new(
        b"POST /chunk HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n"
            .to_vec(),
    );

    let error = read_http_request(&mut reader).unwrap_err();

    assert!(matches!(error, HttpError::UnsupportedTransferEncoding));
}
