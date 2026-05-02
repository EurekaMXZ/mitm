//! Blocking HTTP/1.1 transaction loop over replayable downstream streams.

use std::{
    io::{self, Write},
    net::{Shutdown, TcpStream},
};

use crate::{
    classify::ReplayStream,
    handler::StreamSlot,
    session::{CloseReason, Session, Transaction, TransactionId},
    upstream::connect_http_upstream,
};

use super::{
    read_http_request, read_http_response, write_http_request, write_http_response, HttpError,
    HttpRequestView, HttpResponseView, HttpVersion, RequestReadOutcome,
};

/// Summary produced after an HTTP adapter session finishes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpAdapterReport {
    /// Number of complete request/response transactions processed.
    pub transaction_count: usize,
}

#[derive(Debug)]
struct HttpUpstreamConnection {
    stream: TcpStream,
}

#[derive(Debug)]
struct ProcessTransactionResult {
    informational_responses: Vec<HttpResponseView>,
    final_response: HttpResponseView,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HttpIoPhase {
    UpstreamConnect,
    UpstreamEstablished,
}
/// Blocking HTTP/1.1 adapter that parses requests and forwards them upstream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HttpAdapter;

impl HttpAdapter {
    /// Creates a blocking HTTP adapter.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Runs the blocking HTTP transaction loop until EOF or a close condition.
    ///
    /// # Errors
    ///
    /// Returns [`HttpError`] when downstream or upstream parsing and I/O fail.
    pub fn run(
        &self,
        session: &mut Session,
        stream_slot: StreamSlot,
    ) -> Result<HttpAdapterReport, HttpError> {
        let Ok((prefix, downstream)) = stream_slot.into_replay_parts() else {
            session.close(CloseReason::InternalError);
            return Err(HttpError::Io(std::io::Error::other(
                "http adapter requires a replayable tcp stream",
            )));
        };

        let mut downstream = ReplayStream::new(prefix, downstream);
        let mut upstream: Option<HttpUpstreamConnection> = None;
        let mut transaction_count = 0_usize;

        loop {
            let request = match read_http_request(&mut downstream) {
                Ok(RequestReadOutcome::CleanEof) => {
                    session.close(CloseReason::ClientClosed);
                    break;
                }
                Ok(RequestReadOutcome::Request(request)) => request,
                Err(error) => {
                    session.close(CloseReason::ProtocolError);
                    return Err(error);
                }
            };

            let mut transaction = Transaction::new(
                TransactionId::new((transaction_count + 1) as u64),
                session.id,
            );
            transaction.record_request(request.clone());
            transaction.mark_upstream_pending();

            let response_result = match process_transaction(session, &mut upstream, &request) {
                Ok(response_result) => response_result,
                Err((error, phase)) => {
                    close_upstream_connection(&mut upstream);
                    session.close(close_reason_for_http_error(&error, phase));
                    return Err(error);
                }
            };

            transaction.mark_response_reading();
            for response in &response_result.informational_responses {
                write_http_response(&mut downstream, response)
                    .map_err(|error| close_downstream_error(session, error))?;
            }

            let response = response_result.final_response;
            transaction.record_response(response.clone());

            write_http_response(&mut downstream, &response)
                .map_err(|error| close_downstream_error(session, error))?;
            downstream
                .flush()
                .map_err(|error| close_downstream_error(session, error))?;

            transaction.mark_completed();
            transaction_count += 1;

            if response.status == 101 {
                close_upstream_connection(&mut upstream);
                session.close(CloseReason::UpstreamClosed);
                break;
            }

            if response.body_framing == super::HttpBodyFraming::ConnectionClose {
                close_upstream_connection(&mut upstream);
                session.close(CloseReason::UpstreamClosed);
                break;
            }

            if should_close_session(&request, &response) {
                close_upstream_connection(&mut upstream);
                session.close(CloseReason::UpstreamClosed);
                break;
            }
        }

        Ok(HttpAdapterReport { transaction_count })
    }
}

impl Default for HttpAdapter {
    fn default() -> Self {
        Self::new()
    }
}

fn should_close_session(request: &HttpRequestView, response: &HttpResponseView) -> bool {
    request.connection_close_requested()
        || response.connection_close_requested()
        || request.version == HttpVersion::Http10
        || response.version == HttpVersion::Http10
}

fn should_drop_upstream_after_response(
    request: &HttpRequestView,
    response: &HttpResponseView,
) -> bool {
    should_close_session(request, response)
}

fn process_transaction(
    session: &Session,
    upstream: &mut Option<HttpUpstreamConnection>,
    request: &HttpRequestView,
) -> Result<ProcessTransactionResult, (HttpError, HttpIoPhase)> {
    if upstream.is_none() {
        let stream = connect_http_upstream(&session.target)
            .map_err(HttpError::from)
            .map_err(|error| (error, HttpIoPhase::UpstreamConnect))?;
        *upstream = Some(HttpUpstreamConnection { stream });
    }

    let upstream = upstream
        .as_mut()
        .expect("upstream is initialized before request forwarding");
    write_http_request(&mut upstream.stream, request)
        .map_err(HttpError::from)
        .map_err(|error| (error, HttpIoPhase::UpstreamEstablished))?;
    upstream
        .stream
        .flush()
        .map_err(HttpError::from)
        .map_err(|error| (error, HttpIoPhase::UpstreamEstablished))?;

    let mut responses = Vec::new();
    loop {
        let response = read_http_response(&mut upstream.stream, &request.method)
            .map_err(|error| (error, HttpIoPhase::UpstreamEstablished))?;
        let is_informational = is_interim_response(response.status);
        responses.push(response);
        if !is_informational {
            break;
        }
    }

    for response in &responses {
        if should_drop_upstream_after_response(request, response) {
            let _ = upstream.stream.shutdown(Shutdown::Both);
        }
    }

    let final_response = responses
        .pop()
        .ok_or((HttpError::UnexpectedEof, HttpIoPhase::UpstreamEstablished))?;
    Ok(ProcessTransactionResult {
        informational_responses: responses,
        final_response,
    })
}

fn close_upstream_connection(upstream: &mut Option<HttpUpstreamConnection>) {
    if let Some(connection) = upstream.take() {
        let _ = connection.stream.shutdown(Shutdown::Both);
    }
}

fn close_reason_for_http_error(error: &HttpError, phase: HttpIoPhase) -> CloseReason {
    match phase {
        HttpIoPhase::UpstreamConnect => CloseReason::UpstreamConnectFailed,
        HttpIoPhase::UpstreamEstablished => match error {
            HttpError::Io(_) | HttpError::UnexpectedEof => CloseReason::UpstreamClosed,
            _ => CloseReason::ProtocolError,
        },
    }
}

fn close_downstream_error(session: &mut Session, error: io::Error) -> HttpError {
    session.close(CloseReason::TunnelIoError);
    HttpError::Io(error)
}

fn is_interim_response(status: u16) -> bool {
    (100..200).contains(&status) && status != 101
}
