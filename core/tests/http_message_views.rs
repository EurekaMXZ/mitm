//! HTTP message view behavior tests.

use mitm_core::http::{
    HttpBodyFraming, HttpMessageView, HttpRequestView, HttpResponseView, HttpVersion, RawHeader,
};

#[test]
fn http_request_view_preserves_raw_header_fidelity_and_lookup_order() {
    let request = HttpRequestView::new(
        "GET",
        "/demo?x=1",
        HttpVersion::Http11,
        vec![
            RawHeader::new("Host", "example.com"),
            RawHeader::new("x-demo", "1"),
            RawHeader::new("X-Demo", "2"),
            RawHeader::new("Accept", "*/*"),
        ],
        b"payload".to_vec(),
        HttpBodyFraming::ContentLength(7),
    );

    assert_eq!(request.headers().len(), 4);
    assert_eq!(request.headers()[0], RawHeader::new("Host", "example.com"));
    assert_eq!(request.headers()[1], RawHeader::new("x-demo", "1"));
    assert_eq!(request.headers()[2], RawHeader::new("X-Demo", "2"));
    assert_eq!(request.headers()[3], RawHeader::new("Accept", "*/*"));
    assert_eq!(request.header_values("x-demo"), vec!["1", "2"]);
}

#[test]
fn http_request_view_http11_uses_keep_alive_by_default() {
    let request = HttpRequestView::new(
        "GET",
        "/",
        HttpVersion::Http11,
        Vec::new(),
        Vec::new(),
        HttpBodyFraming::None,
    );

    assert!(request.keep_alive_by_default());
}

#[test]
fn http_request_view_http10_does_not_use_keep_alive_by_default() {
    let request = HttpRequestView::new(
        "GET",
        "/",
        HttpVersion::Http10,
        Vec::new(),
        Vec::new(),
        HttpBodyFraming::None,
    );

    assert!(!request.keep_alive_by_default());
}

#[test]
fn http_response_view_distinguishes_default_keep_alive_by_version() {
    let http11_response = HttpResponseView::new(
        HttpVersion::Http11,
        200,
        "OK",
        Vec::new(),
        Vec::new(),
        HttpBodyFraming::None,
    );
    let http10_response = HttpResponseView::new(
        HttpVersion::Http10,
        200,
        "OK",
        Vec::new(),
        Vec::new(),
        HttpBodyFraming::None,
    );

    assert!(http11_response.keep_alive_by_default());
    assert!(!http10_response.keep_alive_by_default());
}

#[test]
fn http_message_view_exposes_keep_alive_by_default_for_both_directions() {
    let request = HttpMessageView::Request(HttpRequestView::new(
        "GET",
        "/",
        HttpVersion::Http11,
        Vec::new(),
        Vec::new(),
        HttpBodyFraming::None,
    ));
    let response = HttpMessageView::Response(HttpResponseView::new(
        HttpVersion::Http10,
        200,
        "OK",
        Vec::new(),
        Vec::new(),
        HttpBodyFraming::None,
    ));

    assert!(request.keep_alive_by_default());
    assert!(!response.keep_alive_by_default());
}

#[test]
fn http_response_view_exposes_status_reason_body_and_chunked_framing() {
    let response = HttpResponseView::new(
        HttpVersion::Http11,
        200,
        "OK",
        vec![RawHeader::new("Transfer-Encoding", "chunked")],
        b"hello".to_vec(),
        HttpBodyFraming::Chunked,
    );

    assert_eq!(response.status, 200);
    assert_eq!(response.reason_phrase, "OK");
    assert_eq!(response.body, b"hello");
    assert_eq!(response.body_framing, HttpBodyFraming::Chunked);
}
