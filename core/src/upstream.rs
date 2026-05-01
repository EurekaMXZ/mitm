//! Upstream TCP and TLS connection management.

#![allow(clippy::module_name_repetitions)]

use std::{
    io::{self, Read, Write},
    net::{Shutdown, SocketAddr, TcpStream, ToSocketAddrs},
    sync::{
        atomic::{AtomicU64, AtomicU8, Ordering},
        Arc,
    },
    thread,
    time::{Duration, Instant},
};

use crate::{
    handler::{Handler, HandlerContext, HandlerOutcome, HandlerResult, StreamSlot},
    session::{CloseReason, ProcessingMode, TargetAddr, TargetHost, TlsPolicy},
};

/// Final close reason observed by the raw tunnel copy loop.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RawTunnelCloseReason {
    /// Downstream client finished sending first.
    ClientClosed,
    /// Upstream peer finished sending first.
    UpstreamClosed,
    /// Upstream TCP connection could not be established.
    UpstreamConnectFailed,
    /// Raw tunnel setup or copy failed with an I/O error.
    IoError,
}

/// Report recorded after a raw tunnel session completes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawTunnelReport {
    /// Bytes copied from downstream client to upstream.
    pub client_to_upstream_bytes: u64,
    /// Bytes copied from upstream to downstream client.
    pub upstream_to_client_bytes: u64,
    /// Total tunnel duration.
    pub duration: Duration,
    /// Close reason selected from the copy loop outcome.
    pub close_reason: RawTunnelCloseReason,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum FirstTunnelEvent {
    None = 0,
    ClientClosed = 1,
    UpstreamClosed = 2,
    UpstreamConnectFailed = 3,
    IoError = 4,
}

/// Blocking raw TCP tunnel handler for raw TCP and TLS bypass flows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RawTunnelHandler;

impl RawTunnelHandler {
    /// Creates a blocking raw tunnel handler.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl Default for RawTunnelHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl Handler for RawTunnelHandler {
    fn name(&self) -> &'static str {
        "raw-tunnel"
    }

    fn handle(&self, ctx: &mut HandlerContext) -> HandlerOutcome {
        if !should_tunnel(ctx) {
            return HandlerOutcome {
                decision: None,
                control: HandlerResult::Continue,
            };
        }

        let slot = ctx.stream.take();
        let (prefix, mut downstream) = match slot.into_replay_parts() {
            Ok(parts) => parts,
            Err(slot) => {
                ctx.stream = slot;
                return HandlerOutcome {
                    decision: None,
                    control: HandlerResult::Continue,
                };
            }
        };

        let started_at = Instant::now();
        let report = match run_raw_tunnel(&ctx.session.target, &prefix, &mut downstream) {
            Ok(report) => report,
            Err(reason) => RawTunnelReport {
                client_to_upstream_bytes: 0,
                upstream_to_client_bytes: 0,
                duration: started_at.elapsed(),
                close_reason: reason,
            },
        };

        ctx.raw_tunnel_report = Some(report.clone());
        ctx.stream = StreamSlot::Closed;
        ctx.session.close(map_close_reason(report.close_reason));

        HandlerOutcome {
            decision: None,
            control: HandlerResult::Stop,
        }
    }
}

fn should_tunnel(ctx: &HandlerContext) -> bool {
    ctx.session.mode() == ProcessingMode::RawTunnel
        || ctx.session.tls_policy() == TlsPolicy::Bypass
        || matches!(ctx.session.protocol(), crate::session::ProtocolHint::RawTcp)
}

fn map_close_reason(reason: RawTunnelCloseReason) -> CloseReason {
    match reason {
        RawTunnelCloseReason::ClientClosed => CloseReason::ClientClosed,
        RawTunnelCloseReason::UpstreamClosed => CloseReason::UpstreamClosed,
        RawTunnelCloseReason::UpstreamConnectFailed => CloseReason::UpstreamConnectFailed,
        RawTunnelCloseReason::IoError => CloseReason::TunnelIoError,
    }
}

fn run_raw_tunnel(
    target: &TargetAddr,
    prefix: &[u8],
    downstream: &mut TcpStream,
) -> Result<RawTunnelReport, RawTunnelCloseReason> {
    let started_at = Instant::now();
    let upstream_addr =
        target_to_socket_addr(target).map_err(|_| RawTunnelCloseReason::UpstreamConnectFailed)?;
    let mut upstream = TcpStream::connect(upstream_addr)
        .map_err(|_| RawTunnelCloseReason::UpstreamConnectFailed)?;

    if !prefix.is_empty() {
        upstream
            .write_all(prefix)
            .map_err(|_| RawTunnelCloseReason::IoError)?;
    }

    let downstream_reader = downstream
        .try_clone()
        .map_err(|_| RawTunnelCloseReason::IoError)?;
    let upstream_writer = upstream
        .try_clone()
        .map_err(|_| RawTunnelCloseReason::IoError)?;
    let downstream_writer = downstream
        .try_clone()
        .map_err(|_| RawTunnelCloseReason::IoError)?;

    let client_to_upstream_bytes = Arc::new(AtomicU64::new(prefix.len() as u64));
    let upstream_to_client_bytes = Arc::new(AtomicU64::new(0));
    let first_event = Arc::new(AtomicU8::new(FirstTunnelEvent::None as u8));

    let c2u_counter = Arc::clone(&client_to_upstream_bytes);
    let c2u_first_event = Arc::clone(&first_event);
    let client_to_upstream = thread::spawn(move || {
        copy_until_eof(
            downstream_reader,
            upstream_writer,
            c2u_counter.as_ref(),
            RawTunnelCloseReason::ClientClosed,
            c2u_first_event.as_ref(),
        )
    });

    let u2c_counter = Arc::clone(&upstream_to_client_bytes);
    let upstream_result = copy_until_eof(
        upstream,
        downstream_writer,
        u2c_counter.as_ref(),
        RawTunnelCloseReason::UpstreamClosed,
        first_event.as_ref(),
    );

    let _ = downstream.shutdown(Shutdown::Read);
    let client_result = join_copy_thread(client_to_upstream);
    let _ = downstream.shutdown(Shutdown::Both);

    let first_recorded_event = FirstTunnelEvent::from_raw(first_event.load(Ordering::Relaxed));
    let close_reason = select_close_reason(first_recorded_event, upstream_result, client_result);

    Ok(RawTunnelReport {
        client_to_upstream_bytes: client_to_upstream_bytes.load(Ordering::Relaxed),
        upstream_to_client_bytes: upstream_to_client_bytes.load(Ordering::Relaxed),
        duration: started_at.elapsed(),
        close_reason,
    })
}

fn join_copy_thread(
    handle: thread::JoinHandle<Result<RawTunnelCloseReason, RawTunnelCloseReason>>,
) -> Result<RawTunnelCloseReason, RawTunnelCloseReason> {
    match handle.join() {
        Ok(result) => result,
        Err(_) => Err(RawTunnelCloseReason::IoError),
    }
}
fn copy_until_eof(
    mut reader: TcpStream,
    mut writer: TcpStream,
    counter: &AtomicU64,
    eof_reason: RawTunnelCloseReason,
    first_event: &AtomicU8,
) -> Result<RawTunnelCloseReason, RawTunnelCloseReason> {
    let mut buf = [0_u8; 8192];

    loop {
        let read = match reader.read(&mut buf) {
            Ok(0) => {
                record_first_event(first_event, eof_reason);
                let _ = writer.shutdown(Shutdown::Write);
                return Ok(eof_reason);
            }
            Ok(read) => read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => {
                record_first_event(first_event, RawTunnelCloseReason::IoError);
                return Err(RawTunnelCloseReason::IoError);
            }
        };

        writer
            .write_all(&buf[..read])
            .map_err(|_| RawTunnelCloseReason::IoError)?;
        counter.fetch_add(read as u64, Ordering::Relaxed);
    }
}

fn record_first_event(first_event: &AtomicU8, reason: RawTunnelCloseReason) {
    let _ = first_event.compare_exchange(
        FirstTunnelEvent::None as u8,
        FirstTunnelEvent::from(reason) as u8,
        Ordering::Relaxed,
        Ordering::Relaxed,
    );
}

fn first_event_to_reason(event: FirstTunnelEvent) -> RawTunnelCloseReason {
    match event {
        FirstTunnelEvent::ClientClosed => RawTunnelCloseReason::ClientClosed,
        FirstTunnelEvent::UpstreamClosed => RawTunnelCloseReason::UpstreamClosed,
        FirstTunnelEvent::UpstreamConnectFailed => RawTunnelCloseReason::UpstreamConnectFailed,
        FirstTunnelEvent::None | FirstTunnelEvent::IoError => RawTunnelCloseReason::IoError,
    }
}

fn select_close_reason(
    first_event: FirstTunnelEvent,
    upstream_result: Result<RawTunnelCloseReason, RawTunnelCloseReason>,
    client_result: Result<RawTunnelCloseReason, RawTunnelCloseReason>,
) -> RawTunnelCloseReason {
    if matches!(
        first_event,
        FirstTunnelEvent::ClientClosed
            | FirstTunnelEvent::UpstreamClosed
            | FirstTunnelEvent::UpstreamConnectFailed
    ) {
        return first_event_to_reason(first_event);
    }

    match (upstream_result, client_result) {
        (Err(reason), _) | (_, Err(reason)) => reason,
        _ => first_event_to_reason(first_event),
    }
}

impl FirstTunnelEvent {
    fn from_raw(value: u8) -> Self {
        match value {
            1 => Self::ClientClosed,
            2 => Self::UpstreamClosed,
            3 => Self::UpstreamConnectFailed,
            4 => Self::IoError,
            _ => Self::None,
        }
    }
}

impl From<RawTunnelCloseReason> for FirstTunnelEvent {
    fn from(value: RawTunnelCloseReason) -> Self {
        match value {
            RawTunnelCloseReason::ClientClosed => Self::ClientClosed,
            RawTunnelCloseReason::UpstreamClosed => Self::UpstreamClosed,
            RawTunnelCloseReason::UpstreamConnectFailed => Self::UpstreamConnectFailed,
            RawTunnelCloseReason::IoError => Self::IoError,
        }
    }
}

fn target_to_socket_addr(target: &TargetAddr) -> io::Result<SocketAddr> {
    match target.host() {
        TargetHost::Ip(ip) => Ok(SocketAddr::new(*ip, target.port())),
        TargetHost::Domain(domain) => {
            (domain.as_str(), target.port())
                .to_socket_addrs()
                .and_then(|mut addrs| {
                    addrs.next().ok_or_else(|| {
                        io::Error::new(io::ErrorKind::NotFound, "no upstream address resolved")
                    })
                })
        }
    }
}
