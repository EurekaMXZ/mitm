//! Blocking HTTP adapter transaction loop tests.

use std::{
    io::{Read, Write},
    net::{Shutdown, SocketAddr, TcpListener, TcpStream},
    thread,
    time::Duration,
};

use mitm_core::{
    handler::StreamSlot,
    http::HttpAdapter,
    session::{
        ApplicationProtocol, CloseReason, IngressSource, ProcessingMode, ProtocolHint, Session,
        SessionId, SessionState, TargetAddr, TlsPolicy,
    },
};

fn connected_stream_pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).unwrap();
    let addr = listener.local_addr().unwrap();
    let client = TcpStream::connect(addr).unwrap();
    let (server, _) = listener.accept().unwrap();
    (server, client)
}

fn bind_upstream_listener() -> (TcpListener, TargetAddr) {
    let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).unwrap();
    let addr = listener.local_addr().unwrap();
    let target = TargetAddr::ip(addr.ip(), addr.port()).unwrap();
    (listener, target)
}

fn unresolved_target_addr() -> TargetAddr {
    TargetAddr::domain("nonexistent.invalid", 80).unwrap()
}

fn refused_target_addr() -> TargetAddr {
    let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    TargetAddr::ip(addr.ip(), addr.port()).unwrap()
}

fn configure_stream(stream: &TcpStream) {
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(2)))
        .unwrap();
}

fn test_session(target: TargetAddr) -> Session {
    let client = SocketAddr::from(([127, 0, 0, 1], 50_100));
    let listener = SocketAddr::from(([127, 0, 0, 1], 1080));
    let source = IngressSource::Socks5 { listener, client };
    let mut session = Session::new(SessionId::new(11), client, target, source);
    session.set_state(SessionState::InspectingHttp);
    session.set_mode(ProcessingMode::Inspect);
    session.set_protocol(ProtocolHint::Http1);
    session.set_tls_policy(TlsPolicy::Undecided);
    session.set_application_protocol(ApplicationProtocol::Http1);
    session
}

#[test]
fn http_adapter_round_trips_single_get_transaction() {
    let replayed_prefix = b"GET ".to_vec();
    let client_suffix = b"/ HTTP/1.1\r\nHost: example.com\r\n\r\n".to_vec();
    let expected_request = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n".to_vec();
    let expected_response = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok".to_vec();
    let expected_request_for_upstream = expected_request.clone();
    let expected_response_for_upstream = expected_response.clone();

    let (upstream_listener, target) = bind_upstream_listener();
    let upstream_thread = thread::spawn(move || {
        let (mut upstream_stream, _) = upstream_listener.accept().unwrap();
        drop(upstream_listener);
        configure_stream(&upstream_stream);

        let mut request = vec![0_u8; expected_request_for_upstream.len()];
        upstream_stream.read_exact(&mut request).unwrap();
        assert_eq!(request, expected_request_for_upstream);

        upstream_stream
            .write_all(&expected_response_for_upstream)
            .unwrap();
        upstream_stream.shutdown(Shutdown::Write).unwrap();
    });

    let (downstream_server, mut downstream_client) = connected_stream_pair();
    configure_stream(&downstream_client);
    let client_thread = thread::spawn(move || {
        downstream_client.write_all(&client_suffix).unwrap();
        downstream_client.shutdown(Shutdown::Write).unwrap();

        let mut response = Vec::new();
        downstream_client.read_to_end(&mut response).unwrap();
        response
    });

    let mut session = test_session(target);
    let report = HttpAdapter::new()
        .run(
            &mut session,
            StreamSlot::Peeked {
                prefix: replayed_prefix,
                stream: downstream_server,
            },
        )
        .unwrap();

    assert_eq!(report.transaction_count, 1);
    assert_eq!(client_thread.join().unwrap(), expected_response);
    upstream_thread.join().unwrap();
}

#[test]
fn http_adapter_round_trips_single_post_transaction() {
    let request =
        b"POST /submit HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\n\r\nhello".to_vec();
    let response = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok".to_vec();
    let upstream_request = request.clone();
    let expected_response = response.clone();

    let (upstream_listener, target) = bind_upstream_listener();
    let upstream_thread = thread::spawn(move || {
        let (mut upstream_stream, _) = upstream_listener.accept().unwrap();
        drop(upstream_listener);
        configure_stream(&upstream_stream);

        let mut request_buf = vec![0_u8; upstream_request.len()];
        upstream_stream.read_exact(&mut request_buf).unwrap();
        assert_eq!(request_buf, upstream_request);
        upstream_stream.write_all(&response).unwrap();
        upstream_stream.shutdown(Shutdown::Write).unwrap();
    });

    let (downstream_server, mut downstream_client) = connected_stream_pair();
    configure_stream(&downstream_client);
    let client_thread = thread::spawn(move || {
        downstream_client.write_all(&request).unwrap();
        downstream_client.shutdown(Shutdown::Write).unwrap();

        let mut response = Vec::new();
        downstream_client.read_to_end(&mut response).unwrap();
        response
    });

    let mut session = test_session(target);
    let report = HttpAdapter::new()
        .run(&mut session, StreamSlot::Raw(downstream_server))
        .unwrap();

    assert_eq!(report.transaction_count, 1);
    assert_eq!(client_thread.join().unwrap(), expected_response);
    upstream_thread.join().unwrap();
}

#[test]
fn http_adapter_reuses_upstream_connection_for_keep_alive() {
    let request_a = b"GET /a HTTP/1.1\r\nHost: example.com\r\n\r\n".to_vec();
    let request_b = b"GET /b HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n".to_vec();
    let response_a = b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\na".to_vec();
    let response_b = b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nConnection: close\r\n\r\nb".to_vec();
    let first_request_bytes = request_a.clone();
    let second_request_bytes = request_b.clone();
    let first_response_bytes = response_a.clone();
    let second_response_bytes = response_b.clone();

    let (upstream_listener, target) = bind_upstream_listener();
    let upstream_thread = thread::spawn(move || {
        let (mut upstream_stream, _) = upstream_listener.accept().unwrap();
        drop(upstream_listener);
        configure_stream(&upstream_stream);

        let mut first_request = vec![0_u8; first_request_bytes.len()];
        upstream_stream.read_exact(&mut first_request).unwrap();
        assert_eq!(first_request, first_request_bytes);
        upstream_stream.write_all(&first_response_bytes).unwrap();

        let mut second_request = vec![0_u8; second_request_bytes.len()];
        upstream_stream.read_exact(&mut second_request).unwrap();
        assert_eq!(second_request, second_request_bytes);
        upstream_stream.write_all(&second_response_bytes).unwrap();
        upstream_stream.shutdown(Shutdown::Write).unwrap();

        1_usize
    });

    let (downstream_server, mut downstream_client) = connected_stream_pair();
    configure_stream(&downstream_client);
    let client_thread = thread::spawn(move || {
        let mut requests = Vec::new();
        requests.extend_from_slice(&request_a);
        requests.extend_from_slice(&request_b);

        downstream_client.write_all(&requests).unwrap();
        downstream_client.shutdown(Shutdown::Write).unwrap();

        let mut responses = Vec::new();
        downstream_client.read_to_end(&mut responses).unwrap();
        responses
    });

    let mut session = test_session(target);
    let report = HttpAdapter::new()
        .run(&mut session, StreamSlot::Raw(downstream_server))
        .unwrap();

    let mut expected_responses = Vec::new();
    expected_responses.extend_from_slice(&response_a);
    expected_responses.extend_from_slice(&response_b);

    assert_eq!(report.transaction_count, 2);
    assert_eq!(upstream_thread.join().unwrap(), 1);
    assert_eq!(client_thread.join().unwrap(), expected_responses);
}

#[test]
fn http_adapter_closes_session_when_response_body_uses_connection_close_framing() {
    let request = b"GET /close HTTP/1.1\r\nHost: example.com\r\n\r\n".to_vec();
    let response = b"HTTP/1.1 200 OK\r\n\r\npayload".to_vec();
    let upstream_request = request.clone();
    let upstream_response = response.clone();

    let (upstream_listener, target) = bind_upstream_listener();
    let upstream_thread = thread::spawn(move || {
        let (mut upstream_stream, _) = upstream_listener.accept().unwrap();
        drop(upstream_listener);
        configure_stream(&upstream_stream);

        let mut request_buf = vec![0_u8; upstream_request.len()];
        upstream_stream.read_exact(&mut request_buf).unwrap();
        assert_eq!(request_buf, upstream_request);
        upstream_stream.write_all(&upstream_response).unwrap();
        upstream_stream.shutdown(Shutdown::Write).unwrap();
    });

    let (downstream_server, mut downstream_client) = connected_stream_pair();
    configure_stream(&downstream_client);
    let expected_response = response.clone();
    let client_thread = thread::spawn(move || {
        downstream_client.write_all(&request).unwrap();
        downstream_client.shutdown(Shutdown::Write).unwrap();

        let mut response = Vec::new();
        downstream_client.read_to_end(&mut response).unwrap();
        response
    });

    let mut session = test_session(target);
    let report = HttpAdapter::new()
        .run(&mut session, StreamSlot::Raw(downstream_server))
        .unwrap();

    assert_eq!(report.transaction_count, 1);
    assert_eq!(client_thread.join().unwrap(), expected_response);
    upstream_thread.join().unwrap();
    assert_eq!(session.close_reason(), Some(CloseReason::UpstreamClosed));
}

#[test]
fn http_adapter_records_upstream_connect_failed_reason() {
    let request = b"GET /fail HTTP/1.1\r\nHost: example.com\r\n\r\n".to_vec();
    let target = refused_target_addr();

    let (downstream_server, mut downstream_client) = connected_stream_pair();
    configure_stream(&downstream_client);
    let client_thread = thread::spawn(move || {
        downstream_client.write_all(&request).unwrap();
        downstream_client.shutdown(Shutdown::Write).unwrap();
    });

    let mut session = test_session(target);
    let error = HttpAdapter::new()
        .run(&mut session, StreamSlot::Raw(downstream_server))
        .unwrap_err();

    assert!(matches!(error, mitm_core::http::HttpError::Io(_)));
    client_thread.join().unwrap();
    assert_eq!(
        session.close_reason(),
        Some(CloseReason::UpstreamConnectFailed)
    );
}

#[test]
fn http_adapter_reads_final_response_after_informational_response() {
    let request = b"GET /info HTTP/1.1\r\nHost: example.com\r\n\r\n".to_vec();
    let informational = b"HTTP/1.1 100 Continue\r\n\r\n".to_vec();
    let final_response = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok".to_vec();
    let upstream_request = request.clone();
    let expected_downstream = [informational.clone(), final_response.clone()].concat();

    let (upstream_listener, target) = bind_upstream_listener();
    let upstream_thread = thread::spawn(move || {
        let (mut upstream_stream, _) = upstream_listener.accept().unwrap();
        drop(upstream_listener);
        configure_stream(&upstream_stream);

        let mut request_buf = vec![0_u8; upstream_request.len()];
        upstream_stream.read_exact(&mut request_buf).unwrap();
        assert_eq!(request_buf, upstream_request);

        upstream_stream.write_all(&informational).unwrap();
        upstream_stream.write_all(&final_response).unwrap();
        upstream_stream.shutdown(Shutdown::Write).unwrap();
    });

    let (downstream_server, mut downstream_client) = connected_stream_pair();
    configure_stream(&downstream_client);
    let client_thread = thread::spawn(move || {
        downstream_client.write_all(&request).unwrap();
        downstream_client.shutdown(Shutdown::Write).unwrap();

        let mut response = Vec::new();
        downstream_client.read_to_end(&mut response).unwrap();
        response
    });

    let mut session = test_session(target);
    let report = HttpAdapter::new()
        .run(&mut session, StreamSlot::Raw(downstream_server))
        .unwrap();

    assert_eq!(report.transaction_count, 1);
    assert_eq!(client_thread.join().unwrap(), expected_downstream);
    upstream_thread.join().unwrap();
}

#[test]
fn http_adapter_treats_switching_protocols_as_final_response() {
    let request = b"GET /upgrade HTTP/1.1\r\nHost: example.com\r\n\r\n".to_vec();
    let switching_protocols =
        b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n"
            .to_vec();
    let upstream_request = request.clone();
    let expected_downstream = switching_protocols.clone();

    let (upstream_listener, target) = bind_upstream_listener();
    let upstream_thread = thread::spawn(move || {
        let (mut upstream_stream, _) = upstream_listener.accept().unwrap();
        drop(upstream_listener);
        configure_stream(&upstream_stream);

        let mut request_buf = vec![0_u8; upstream_request.len()];
        upstream_stream.read_exact(&mut request_buf).unwrap();
        assert_eq!(request_buf, upstream_request);

        upstream_stream.write_all(&switching_protocols).unwrap();
        thread::sleep(Duration::from_millis(200));
    });

    let (downstream_server, mut downstream_client) = connected_stream_pair();
    configure_stream(&downstream_client);
    let client_thread = thread::spawn(move || {
        downstream_client.write_all(&request).unwrap();
        downstream_client.shutdown(Shutdown::Write).unwrap();

        let mut response = Vec::new();
        downstream_client.read_to_end(&mut response).unwrap();
        response
    });

    let mut session = test_session(target);
    let report = HttpAdapter::new()
        .run(&mut session, StreamSlot::Raw(downstream_server))
        .unwrap();

    assert_eq!(report.transaction_count, 1);
    assert_eq!(client_thread.join().unwrap(), expected_downstream);
    upstream_thread.join().unwrap();
    assert_eq!(session.close_reason(), Some(CloseReason::UpstreamClosed));
}

#[test]
fn http_adapter_records_dns_resolution_failure_as_upstream_connect_failed() {
    let request = b"GET /dns-fail HTTP/1.1\r\nHost: example.com\r\n\r\n".to_vec();
    let target = unresolved_target_addr();

    let (downstream_server, mut downstream_client) = connected_stream_pair();
    configure_stream(&downstream_client);
    let client_thread = thread::spawn(move || {
        downstream_client.write_all(&request).unwrap();
        downstream_client.shutdown(Shutdown::Write).unwrap();
    });

    let mut session = test_session(target);
    let error = HttpAdapter::new()
        .run(&mut session, StreamSlot::Raw(downstream_server))
        .unwrap_err();

    assert!(matches!(error, mitm_core::http::HttpError::Io(_)));
    client_thread.join().unwrap();
    assert_eq!(
        session.close_reason(),
        Some(CloseReason::UpstreamConnectFailed)
    );
}

#[test]
fn http_adapter_http10_defaults_to_connection_close() {
    let request = b"GET /legacy HTTP/1.0\r\nHost: example.com\r\n\r\n".to_vec();
    let response = b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nok".to_vec();
    let upstream_request = request.clone();
    let expected_response = response.clone();

    let (upstream_listener, target) = bind_upstream_listener();
    let upstream_thread = thread::spawn(move || {
        let (mut upstream_stream, _) = upstream_listener.accept().unwrap();
        drop(upstream_listener);
        configure_stream(&upstream_stream);

        let mut request_buf = vec![0_u8; upstream_request.len()];
        upstream_stream.read_exact(&mut request_buf).unwrap();
        assert_eq!(request_buf, upstream_request);
        upstream_stream.write_all(&response).unwrap();
        upstream_stream.shutdown(Shutdown::Write).unwrap();
    });

    let (downstream_server, mut downstream_client) = connected_stream_pair();
    configure_stream(&downstream_client);
    let client_thread = thread::spawn(move || {
        downstream_client.write_all(&request).unwrap();
        downstream_client.shutdown(Shutdown::Write).unwrap();

        let mut response = Vec::new();
        downstream_client.read_to_end(&mut response).unwrap();
        response
    });

    let mut session = test_session(target);
    let report = HttpAdapter::new()
        .run(&mut session, StreamSlot::Raw(downstream_server))
        .unwrap();

    assert_eq!(report.transaction_count, 1);
    assert_eq!(client_thread.join().unwrap(), expected_response);
    upstream_thread.join().unwrap();
    assert_eq!(session.close_reason(), Some(CloseReason::UpstreamClosed));
}

#[test]
fn http_adapter_records_client_closed_on_clean_downstream_eof_after_response() {
    let request = b"GET /eof HTTP/1.1\r\nHost: example.com\r\n\r\n".to_vec();
    let response = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok".to_vec();
    let upstream_request = request.clone();
    let upstream_response = response.clone();

    let (upstream_listener, target) = bind_upstream_listener();
    let upstream_thread = thread::spawn(move || {
        let (mut upstream_stream, _) = upstream_listener.accept().unwrap();
        drop(upstream_listener);
        configure_stream(&upstream_stream);

        let mut request_buf = vec![0_u8; upstream_request.len()];
        upstream_stream.read_exact(&mut request_buf).unwrap();
        assert_eq!(request_buf, upstream_request);
        upstream_stream.write_all(&upstream_response).unwrap();
        upstream_stream.shutdown(Shutdown::Write).unwrap();
    });

    let (downstream_server, mut downstream_client) = connected_stream_pair();
    configure_stream(&downstream_client);
    let expected_response = response.clone();
    let client_thread = thread::spawn(move || {
        downstream_client.write_all(&request).unwrap();
        downstream_client.shutdown(Shutdown::Write).unwrap();

        let mut response = Vec::new();
        downstream_client.read_to_end(&mut response).unwrap();
        response
    });

    let mut session = test_session(target);
    let report = HttpAdapter::new()
        .run(&mut session, StreamSlot::Raw(downstream_server))
        .unwrap();

    assert_eq!(report.transaction_count, 1);
    assert_eq!(client_thread.join().unwrap(), expected_response);
    upstream_thread.join().unwrap();
    assert_eq!(session.close_reason(), Some(CloseReason::ClientClosed));
}

#[test]
fn http_adapter_records_tunnel_io_error_when_downstream_write_fails() {
    let request = b"GET /write-fail HTTP/1.1\r\nHost: example.com\r\n\r\n".to_vec();
    let response = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok".to_vec();
    let upstream_request = request.clone();
    let upstream_response = response.clone();

    let (upstream_listener, target) = bind_upstream_listener();
    let upstream_thread = thread::spawn(move || {
        let (mut upstream_stream, _) = upstream_listener.accept().unwrap();
        drop(upstream_listener);
        configure_stream(&upstream_stream);

        let mut request_buf = vec![0_u8; upstream_request.len()];
        upstream_stream.read_exact(&mut request_buf).unwrap();
        assert_eq!(request_buf, upstream_request);
        thread::sleep(Duration::from_millis(100));
        upstream_stream.write_all(&upstream_response).unwrap();
        upstream_stream.shutdown(Shutdown::Write).unwrap();
    });

    let (downstream_server, mut downstream_client) = connected_stream_pair();
    configure_stream(&downstream_client);
    let client_thread = thread::spawn(move || {
        downstream_client.write_all(&request).unwrap();
        downstream_client.shutdown(Shutdown::Both).unwrap();
    });

    let mut session = test_session(target);
    let error = HttpAdapter::new()
        .run(&mut session, StreamSlot::Raw(downstream_server))
        .unwrap_err();

    assert!(matches!(error, mitm_core::http::HttpError::Io(_)));
    client_thread.join().unwrap();
    upstream_thread.join().unwrap();
    assert_eq!(session.close_reason(), Some(CloseReason::TunnelIoError));
}

#[test]
fn http_adapter_round_trips_chunked_response_body() {
    let request =
        b"GET /chunked HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n".to_vec();
    let upstream_response =
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n5\r\nhello\r\n0\r\n\r\n"
            .to_vec();
    let expected_downstream = upstream_response.clone();
    let upstream_request = request.clone();

    let (upstream_listener, target) = bind_upstream_listener();
    let upstream_thread = thread::spawn(move || {
        let (mut upstream_stream, _) = upstream_listener.accept().unwrap();
        drop(upstream_listener);
        configure_stream(&upstream_stream);

        let mut request_buf = vec![0_u8; upstream_request.len()];
        upstream_stream.read_exact(&mut request_buf).unwrap();
        assert_eq!(request_buf, upstream_request);
        upstream_stream.write_all(&upstream_response).unwrap();
        upstream_stream.shutdown(Shutdown::Write).unwrap();
    });

    let (downstream_server, mut downstream_client) = connected_stream_pair();
    configure_stream(&downstream_client);
    let client_thread = thread::spawn(move || {
        downstream_client.write_all(&request).unwrap();
        downstream_client.shutdown(Shutdown::Write).unwrap();

        let mut response = Vec::new();
        downstream_client.read_to_end(&mut response).unwrap();
        response
    });

    let mut session = test_session(target);
    let report = HttpAdapter::new()
        .run(&mut session, StreamSlot::Raw(downstream_server))
        .unwrap();

    assert_eq!(report.transaction_count, 1);
    assert_eq!(client_thread.join().unwrap(), expected_downstream);
    upstream_thread.join().unwrap();
}

#[test]
fn http_adapter_records_upstream_closed_when_established_upstream_errors() {
    let first_request = b"GET /first HTTP/1.1\r\nHost: example.com\r\n\r\n".to_vec();
    let second_request =
        b"GET /second HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n".to_vec();
    let first_response = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok".to_vec();
    let upstream_first_request = first_request.clone();
    let upstream_second_request = second_request.clone();
    let expected_downstream = first_response.clone();

    let (upstream_listener, target) = bind_upstream_listener();
    let upstream_thread = thread::spawn(move || {
        let (mut upstream_stream, _) = upstream_listener.accept().unwrap();
        drop(upstream_listener);
        configure_stream(&upstream_stream);

        let mut first_request_buf = vec![0_u8; upstream_first_request.len()];
        upstream_stream.read_exact(&mut first_request_buf).unwrap();
        assert_eq!(first_request_buf, upstream_first_request);
        upstream_stream.write_all(&first_response).unwrap();

        let mut second_request_buf = vec![0_u8; upstream_second_request.len()];
        upstream_stream.read_exact(&mut second_request_buf).unwrap();
        assert_eq!(second_request_buf, upstream_second_request);
        upstream_stream.shutdown(Shutdown::Both).unwrap();
    });

    let (downstream_server, mut downstream_client) = connected_stream_pair();
    configure_stream(&downstream_client);
    let requests = [first_request.clone(), second_request.clone()].concat();
    let client_thread = thread::spawn(move || {
        downstream_client.write_all(&requests).unwrap();
        downstream_client.shutdown(Shutdown::Write).unwrap();

        let mut response = Vec::new();
        downstream_client.read_to_end(&mut response).unwrap();
        response
    });

    let mut session = test_session(target);
    let error = HttpAdapter::new()
        .run(&mut session, StreamSlot::Raw(downstream_server))
        .unwrap_err();

    assert!(matches!(error, mitm_core::http::HttpError::UnexpectedEof));
    assert_eq!(client_thread.join().unwrap(), expected_downstream);
    upstream_thread.join().unwrap();
    assert_eq!(session.close_reason(), Some(CloseReason::UpstreamClosed));
}

#[test]
fn http_adapter_processes_pipelined_requests_serially() {
    let first_request = b"GET /one HTTP/1.1\r\nHost: example.com\r\n\r\n".to_vec();
    let second_request =
        b"GET /two HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n".to_vec();
    let first_response = b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\none".to_vec();
    let second_response =
        b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\ntwo".to_vec();
    let upstream_first_request = first_request.clone();
    let upstream_second_request = second_request.clone();
    let expected_downstream = [first_response.clone(), second_response.clone()].concat();

    let (upstream_listener, target) = bind_upstream_listener();
    let upstream_thread = thread::spawn(move || {
        let (mut upstream_stream, _) = upstream_listener.accept().unwrap();
        drop(upstream_listener);
        configure_stream(&upstream_stream);

        let mut first_request_buf = vec![0_u8; upstream_first_request.len()];
        upstream_stream.read_exact(&mut first_request_buf).unwrap();
        assert_eq!(first_request_buf, upstream_first_request);
        upstream_stream.write_all(&first_response).unwrap();

        let mut second_request_buf = vec![0_u8; upstream_second_request.len()];
        upstream_stream.read_exact(&mut second_request_buf).unwrap();
        assert_eq!(second_request_buf, upstream_second_request);
        upstream_stream.write_all(&second_response).unwrap();
        upstream_stream.shutdown(Shutdown::Write).unwrap();
    });

    let (downstream_server, mut downstream_client) = connected_stream_pair();
    configure_stream(&downstream_client);
    let client_thread = thread::spawn(move || {
        let mut pipelined = Vec::new();
        pipelined.extend_from_slice(&first_request);
        pipelined.extend_from_slice(&second_request);

        downstream_client.write_all(&pipelined).unwrap();
        downstream_client.shutdown(Shutdown::Write).unwrap();

        let mut response = Vec::new();
        downstream_client.read_to_end(&mut response).unwrap();
        response
    });

    let mut session = test_session(target);
    let report = HttpAdapter::new()
        .run(&mut session, StreamSlot::Raw(downstream_server))
        .unwrap();

    assert_eq!(report.transaction_count, 2);
    assert_eq!(client_thread.join().unwrap(), expected_downstream);
    upstream_thread.join().unwrap();
}
