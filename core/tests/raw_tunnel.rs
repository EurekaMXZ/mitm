//! Raw tunnel upstream connection and bidirectional copy tests.

use std::{
    io::{Read, Write},
    net::{Shutdown, SocketAddr, TcpListener, TcpStream},
    thread,
    time::Duration,
};

use mitm_core::{
    handler::{Handler, HandlerContext, HandlerPhase, PatchSet, StreamSlot},
    session::{
        CloseReason, IngressSource, ProcessingMode, ProtocolHint, Session, SessionId, SessionState,
        TargetAddr, TlsPolicy,
    },
    upstream::{RawTunnelCloseReason, RawTunnelHandler},
};

fn connected_stream_pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).unwrap();
    let addr = listener.local_addr().unwrap();
    let client = TcpStream::connect(addr).unwrap();
    let (server, _) = listener.accept().unwrap();
    (server, client)
}

fn test_session(target: TargetAddr) -> Session {
    let client = SocketAddr::from(([127, 0, 0, 1], 50_100));
    let listener = SocketAddr::from(([127, 0, 0, 1], 1080));
    let source = IngressSource::Socks5 { listener, client };
    let mut session = Session::new(SessionId::new(7), client, target, source);
    session.set_state(SessionState::RawTunneling);
    session.set_mode(ProcessingMode::RawTunnel);
    session.set_protocol(ProtocolHint::RawTcp);
    session.set_tls_policy(TlsPolicy::Undecided);
    session
}

fn raw_tunnel_context(stream: StreamSlot, target: TargetAddr) -> HandlerContext {
    HandlerContext {
        phase: HandlerPhase::Connect,
        session: test_session(target),
        stream,
        pending_patches: PatchSet::default(),
        pause: None,
        drop_action: None,
        mock_response: None,
        audit_events: Vec::new(),
        raw_tunnel_report: None,
    }
}

fn bind_upstream_listener() -> (TcpListener, TargetAddr) {
    let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).unwrap();
    let addr = listener.local_addr().unwrap();
    let target = TargetAddr::ip(addr.ip(), addr.port()).unwrap();
    (listener, target)
}

fn refused_target_addr() -> TargetAddr {
    let probe = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).unwrap();
    let addr = probe.local_addr().unwrap();
    drop(probe);
    TargetAddr::ip(addr.ip(), addr.port()).unwrap()
}

#[test]
fn raw_tunnel_handler_replays_prefix_before_bidirectional_copy() {
    let (upstream_listener, target) = bind_upstream_listener();
    let upstream_thread = thread::spawn(move || {
        let (mut upstream_stream, _) = upstream_listener.accept().unwrap();
        upstream_stream
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();

        let mut replayed = [0_u8; 12];
        upstream_stream.read_exact(&mut replayed).unwrap();
        upstream_stream.shutdown(Shutdown::Both).unwrap();
        replayed.to_vec()
    });

    let (downstream_server, downstream_client) = connected_stream_pair();
    downstream_client.shutdown(Shutdown::Both).unwrap();

    let mut ctx = raw_tunnel_context(
        StreamSlot::Peeked {
            prefix: b"hello-prefix".to_vec(),
            stream: downstream_server,
        },
        target,
    );

    let handler = RawTunnelHandler::new();
    let outcome = handler.handle(&mut ctx);

    assert_eq!(outcome.control, mitm_core::handler::HandlerResult::Stop);
    assert_eq!(upstream_thread.join().unwrap(), b"hello-prefix".to_vec());

    let report = ctx
        .raw_tunnel_report
        .expect("raw tunnel report is recorded");
    assert_eq!(report.client_to_upstream_bytes, 12);
    assert_eq!(report.upstream_to_client_bytes, 0);
}

#[test]
fn raw_tunnel_handler_copies_both_directions_and_counts_bytes() {
    let (upstream_listener, target) = bind_upstream_listener();
    let upstream_thread = thread::spawn(move || {
        let (mut upstream_stream, _) = upstream_listener.accept().unwrap();
        upstream_stream
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        upstream_stream
            .set_write_timeout(Some(Duration::from_secs(1)))
            .unwrap();

        let mut request = [0_u8; 10];
        upstream_stream.read_exact(&mut request).unwrap();
        upstream_stream.write_all(b"upstream-ok").unwrap();
        upstream_stream.shutdown(Shutdown::Write).unwrap();
        request.to_vec()
    });

    let (downstream_server, mut downstream_client) = connected_stream_pair();
    let client_thread = thread::spawn(move || {
        downstream_client
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        downstream_client.write_all(b"client-msg").unwrap();
        downstream_client.shutdown(Shutdown::Write).unwrap();

        let mut response = [0_u8; 11];
        downstream_client.read_exact(&mut response).unwrap();
        response.to_vec()
    });

    let mut ctx = raw_tunnel_context(StreamSlot::Raw(downstream_server), target);
    let handler = RawTunnelHandler::new();
    let outcome = handler.handle(&mut ctx);

    assert_eq!(outcome.control, mitm_core::handler::HandlerResult::Stop);
    assert_eq!(upstream_thread.join().unwrap(), b"client-msg".to_vec());
    assert_eq!(client_thread.join().unwrap(), b"upstream-ok".to_vec());

    let report = ctx
        .raw_tunnel_report
        .expect("raw tunnel report is recorded");
    assert_eq!(report.client_to_upstream_bytes, 10);
    assert_eq!(report.upstream_to_client_bytes, 11);
}

#[test]
fn raw_tunnel_handler_records_upstream_closed_reason() {
    let (upstream_listener, target) = bind_upstream_listener();
    let upstream_thread = thread::spawn(move || {
        let (mut upstream_stream, _) = upstream_listener.accept().unwrap();
        upstream_stream.write_all(b"bye").unwrap();
        upstream_stream.shutdown(Shutdown::Both).unwrap();
    });

    let (downstream_server, mut downstream_client) = connected_stream_pair();
    let client_thread = thread::spawn(move || {
        downstream_client
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let mut response = Vec::new();
        downstream_client.read_to_end(&mut response).unwrap();
        response
    });

    let mut ctx = raw_tunnel_context(StreamSlot::Raw(downstream_server), target);
    let handler = RawTunnelHandler::new();
    let outcome = handler.handle(&mut ctx);

    assert_eq!(outcome.control, mitm_core::handler::HandlerResult::Stop);
    upstream_thread.join().unwrap();
    assert_eq!(client_thread.join().unwrap(), b"bye".to_vec());

    let report = ctx
        .raw_tunnel_report
        .expect("raw tunnel report is recorded");
    assert_eq!(report.close_reason, RawTunnelCloseReason::UpstreamClosed);
    assert_eq!(report.upstream_to_client_bytes, 3);
}

#[test]
fn raw_tunnel_handler_records_client_closed_reason() {
    let (upstream_listener, target) = bind_upstream_listener();
    let upstream_thread = thread::spawn(move || {
        let (mut upstream_stream, _) = upstream_listener.accept().unwrap();
        upstream_stream
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();

        let mut received = Vec::new();
        upstream_stream.read_to_end(&mut received).unwrap();
        received
    });

    let (downstream_server, mut downstream_client) = connected_stream_pair();
    let client_thread = thread::spawn(move || {
        downstream_client.write_all(b"client-only").unwrap();
        downstream_client.shutdown(Shutdown::Write).unwrap();
    });

    let mut ctx = raw_tunnel_context(StreamSlot::Raw(downstream_server), target);
    let handler = RawTunnelHandler::new();
    let outcome = handler.handle(&mut ctx);

    assert_eq!(outcome.control, mitm_core::handler::HandlerResult::Stop);
    client_thread.join().unwrap();
    assert_eq!(upstream_thread.join().unwrap(), b"client-only".to_vec());

    let report = ctx
        .raw_tunnel_report
        .expect("raw tunnel report is recorded");
    assert_eq!(report.close_reason, RawTunnelCloseReason::ClientClosed);
    assert_eq!(report.client_to_upstream_bytes, 11);
    assert_eq!(ctx.session.close_reason(), Some(CloseReason::ClientClosed));
}

#[test]
fn raw_tunnel_handler_records_tunnel_io_error_when_local_downstream_write_is_closed() {
    let (upstream_listener, target) = bind_upstream_listener();
    let upstream_thread = thread::spawn(move || {
        let (mut upstream_stream, _) = upstream_listener.accept().unwrap();
        upstream_stream.write_all(b"reply").unwrap();
        thread::sleep(Duration::from_millis(100));
    });

    let (downstream_server, mut downstream_client) = connected_stream_pair();
    downstream_server.shutdown(Shutdown::Write).unwrap();
    let client_thread = thread::spawn(move || {
        downstream_client
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        thread::sleep(Duration::from_millis(200));
        let mut sink = [0_u8; 16];
        let _ = downstream_client.read(&mut sink);
    });

    let mut ctx = raw_tunnel_context(StreamSlot::Raw(downstream_server), target);
    let handler = RawTunnelHandler::new();
    let outcome = handler.handle(&mut ctx);

    assert_eq!(outcome.control, mitm_core::handler::HandlerResult::Stop);
    client_thread.join().unwrap();
    upstream_thread.join().unwrap();

    let report = ctx
        .raw_tunnel_report
        .expect("raw tunnel report is recorded");
    assert_eq!(report.close_reason, RawTunnelCloseReason::IoError);
    assert_eq!(ctx.session.close_reason(), Some(CloseReason::TunnelIoError));
}

#[test]
fn raw_tunnel_handler_preserves_upstream_closed_when_client_writes_after_close() {
    let (upstream_listener, target) = bind_upstream_listener();
    let upstream_thread = thread::spawn(move || {
        let (mut upstream_stream, _) = upstream_listener.accept().unwrap();
        upstream_stream.write_all(b"bye").unwrap();
        upstream_stream.shutdown(Shutdown::Both).unwrap();
    });

    let (downstream_server, mut downstream_client) = connected_stream_pair();
    let client_thread = thread::spawn(move || {
        downstream_client
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();

        let mut response = [0_u8; 3];
        downstream_client.read_exact(&mut response).unwrap();
        assert_eq!(&response, b"bye");

        thread::sleep(Duration::from_millis(50));
        let _ = downstream_client.write_all(b"after-close");
        let _ = downstream_client.shutdown(Shutdown::Write);
    });

    let mut ctx = raw_tunnel_context(StreamSlot::Raw(downstream_server), target);
    let handler = RawTunnelHandler::new();
    let outcome = handler.handle(&mut ctx);

    assert_eq!(outcome.control, mitm_core::handler::HandlerResult::Stop);
    client_thread.join().unwrap();
    upstream_thread.join().unwrap();

    let report = ctx
        .raw_tunnel_report
        .expect("raw tunnel report is recorded");
    assert_eq!(report.close_reason, RawTunnelCloseReason::UpstreamClosed);
    assert_eq!(
        ctx.session.close_reason(),
        Some(CloseReason::UpstreamClosed)
    );
}

#[test]
fn raw_tunnel_handler_records_session_upstream_connect_failed_reason() {
    let unreachable_target = refused_target_addr();
    let (downstream_server, downstream_client) = connected_stream_pair();
    downstream_client.shutdown(Shutdown::Both).unwrap();

    let mut ctx = raw_tunnel_context(StreamSlot::Raw(downstream_server), unreachable_target);
    let handler = RawTunnelHandler::new();
    let outcome = handler.handle(&mut ctx);

    assert_eq!(outcome.control, mitm_core::handler::HandlerResult::Stop);
    assert_eq!(
        ctx.raw_tunnel_report
            .expect("raw tunnel report is recorded")
            .close_reason,
        RawTunnelCloseReason::UpstreamConnectFailed
    );
    assert_eq!(
        ctx.session.close_reason(),
        Some(CloseReason::UpstreamConnectFailed)
    );
}
