//! HTTP response parser and serialization behavior tests.

use std::io::Cursor;

use mitm_core::http::{
    read_http_response, write_http_request, write_http_response, HttpBodyFraming, HttpRequestView,
    HttpResponseView, HttpVersion, RawHeader,
};

#[test]
fn parser_reads_content_length_response() {
    let mut reader = Cursor::new(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello".to_vec());

    let response = read_http_response(&mut reader, "GET").unwrap();

    assert_eq!(response.version, HttpVersion::Http11);
    assert_eq!(response.status, 200);
    assert_eq!(response.reason_phrase, "OK");
    assert_eq!(response.body, b"hello");
    assert_eq!(response.body_framing, HttpBodyFraming::ContentLength(5));
}

#[test]
fn parser_reads_connection_close_response_body() {
    let mut reader = Cursor::new(b"HTTP/1.1 200 OK\r\n\r\nhello".to_vec());

    let response = read_http_response(&mut reader, "GET").unwrap();

    assert_eq!(response.status, 200);
    assert_eq!(response.body, b"hello");
    assert_eq!(response.body_framing, HttpBodyFraming::ConnectionClose);
}

#[test]
fn parser_treats_head_response_as_bodyless() {
    let mut reader = Cursor::new(b"HTTP/1.1 200 OK\r\nContent-Length: 99\r\n\r\n".to_vec());

    let response = read_http_response(&mut reader, "HEAD").unwrap();

    assert!(response.body.is_empty());
    assert_eq!(response.body_framing, HttpBodyFraming::None);
}

#[test]
fn parser_treats_informational_response_as_bodyless() {
    let mut reader =
        Cursor::new(b"HTTP/1.1 101 Switching Protocols\r\nContent-Length: 7\r\n\r\n".to_vec());

    let response = read_http_response(&mut reader, "GET").unwrap();

    assert!(response.body.is_empty());
    assert_eq!(response.body_framing, HttpBodyFraming::None);
}

#[test]
fn parser_treats_204_and_304_as_bodyless() {
    let mut no_content =
        Cursor::new(b"HTTP/1.1 204 No Content\r\nContent-Length: 7\r\n\r\n".to_vec());
    let mut not_modified =
        Cursor::new(b"HTTP/1.1 304 Not Modified\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec());

    let no_content = read_http_response(&mut no_content, "GET").unwrap();
    let not_modified = read_http_response(&mut not_modified, "GET").unwrap();

    assert!(no_content.body.is_empty());
    assert_eq!(no_content.body_framing, HttpBodyFraming::None);
    assert!(not_modified.body.is_empty());
    assert_eq!(not_modified.body_framing, HttpBodyFraming::None);
}

#[test]
fn serializer_re_emits_chunked_request() {
    let request = HttpRequestView::new(
        "POST",
        "/chunk",
        HttpVersion::Http11,
        vec![RawHeader::new("Transfer-Encoding", "chunked")],
        b"hello".to_vec(),
        HttpBodyFraming::Chunked,
    );

    let mut out = Vec::new();
    write_http_request(&mut out, &request).unwrap();

    assert_eq!(
        out,
        b"POST /chunk HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n"
    );
}

#[test]
fn serializer_emits_single_terminal_chunk_for_empty_chunked_request_body() {
    let request = HttpRequestView::new(
        "POST",
        "/empty",
        HttpVersion::Http11,
        vec![RawHeader::new("Transfer-Encoding", "chunked")],
        Vec::new(),
        HttpBodyFraming::Chunked,
    );

    let mut out = Vec::new();
    write_http_request(&mut out, &request).unwrap();

    assert_eq!(
        out,
        b"POST /empty HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"
    );
}

#[test]
fn serializer_re_emits_chunked_response() {
    let response = HttpResponseView::new(
        HttpVersion::Http11,
        200,
        "OK",
        vec![RawHeader::new("Transfer-Encoding", "chunked")],
        b"hello".to_vec(),
        HttpBodyFraming::Chunked,
    );

    let mut out = Vec::new();
    write_http_response(&mut out, &response).unwrap();

    assert_eq!(
        out,
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n"
    );
}

#[test]
fn serializer_emits_single_terminal_chunk_for_empty_chunked_response_body() {
    let response = HttpResponseView::new(
        HttpVersion::Http11,
        200,
        "OK",
        vec![RawHeader::new("Transfer-Encoding", "chunked")],
        Vec::new(),
        HttpBodyFraming::Chunked,
    );

    let mut out = Vec::new();
    write_http_response(&mut out, &response).unwrap();

    assert_eq!(
        out,
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"
    );
}
