//! HTTP body framing inference and buffered body readers.

use std::io::{self, Read, Write};

use super::{
    parser::{read_crlf_line, read_line_string, HttpError},
    HttpBodyFraming, RawHeader,
};

/// Resolves request body framing from raw headers.
pub(crate) fn determine_request_body_framing(
    headers: &[RawHeader],
) -> Result<HttpBodyFraming, HttpError> {
    let transfer_encoding = transfer_encoding_is_chunked(headers)?;
    let content_length = parse_content_length(headers)?;

    if transfer_encoding && content_length.is_some() {
        return Err(HttpError::ConflictingContentLength);
    }

    if transfer_encoding {
        return Ok(HttpBodyFraming::Chunked);
    }

    if let Some(length) = content_length {
        return Ok(HttpBodyFraming::ContentLength(length));
    }

    Ok(HttpBodyFraming::None)
}

/// Resolves response body framing from raw headers and transaction metadata.
pub(crate) fn determine_response_body_framing(
    request_method: &str,
    status: u16,
    headers: &[RawHeader],
) -> Result<HttpBodyFraming, HttpError> {
    if response_is_bodyless(request_method, status) {
        return Ok(HttpBodyFraming::None);
    }

    let transfer_encoding = transfer_encoding_is_chunked(headers)?;
    let content_length = parse_content_length(headers)?;

    if transfer_encoding && content_length.is_some() {
        return Err(HttpError::ConflictingContentLength);
    }

    if transfer_encoding {
        return Ok(HttpBodyFraming::Chunked);
    }

    if let Some(length) = content_length {
        return Ok(HttpBodyFraming::ContentLength(length));
    }

    Ok(HttpBodyFraming::ConnectionClose)
}

/// Reads a complete buffered body using the provided framing strategy.
pub(crate) fn read_buffered_body<R: Read>(
    reader: &mut R,
    framing: &HttpBodyFraming,
) -> Result<Vec<u8>, HttpError> {
    match framing {
        HttpBodyFraming::None => Ok(Vec::new()),
        HttpBodyFraming::ContentLength(length) => read_content_length_body(reader, *length),
        HttpBodyFraming::Chunked => read_chunked_body(reader),
        HttpBodyFraming::ConnectionClose => read_connection_close_body(reader),
    }
}

fn transfer_encoding_is_chunked(headers: &[RawHeader]) -> Result<bool, HttpError> {
    let mut saw_transfer_encoding = false;
    let mut chunked_count = 0_usize;

    for header in headers {
        if header.name.eq_ignore_ascii_case("Transfer-Encoding") {
            saw_transfer_encoding = true;
            for coding in header.value.split(',') {
                let coding = coding.trim();
                if coding.is_empty() {
                    return Err(HttpError::InvalidTransferEncoding);
                }

                if coding.eq_ignore_ascii_case("chunked") {
                    chunked_count += 1;
                    continue;
                }

                return Err(HttpError::UnsupportedTransferEncoding);
            }
        }
    }

    if !saw_transfer_encoding {
        return Ok(false);
    }

    if chunked_count == 1 {
        Ok(true)
    } else {
        Err(HttpError::UnsupportedTransferEncoding)
    }
}

fn response_is_bodyless(request_method: &str, status: u16) -> bool {
    request_method.eq_ignore_ascii_case("HEAD")
        || (100..200).contains(&status)
        || status == 204
        || status == 304
}

fn parse_content_length(headers: &[RawHeader]) -> Result<Option<usize>, HttpError> {
    let mut lengths = Vec::new();

    for header in headers {
        if header.name.eq_ignore_ascii_case("Content-Length") {
            for value in header.value.split(',') {
                let value = value.trim();
                if value.is_empty() {
                    return Err(HttpError::InvalidContentLength);
                }

                let length = value
                    .parse::<usize>()
                    .map_err(|_| HttpError::InvalidContentLength)?;
                lengths.push(length);
            }
        }
    }

    match lengths.split_first() {
        None => Ok(None),
        Some((first, rest)) if rest.iter().all(|length| length == first) => Ok(Some(*first)),
        Some(_) => Err(HttpError::ConflictingContentLength),
    }
}

fn read_content_length_body<R: Read>(reader: &mut R, length: usize) -> Result<Vec<u8>, HttpError> {
    let mut body = vec![0_u8; length];
    reader.read_exact(&mut body)?;
    Ok(body)
}

fn read_chunked_body<R: Read>(reader: &mut R) -> Result<Vec<u8>, HttpError> {
    let mut body = Vec::new();

    loop {
        let line = read_crlf_line(reader)?.ok_or(HttpError::UnexpectedEof)?;
        let line = read_line_string(line, "chunk size")?;
        let size_text = line
            .split_once(';')
            .map_or(line.as_str(), |(size, _)| size)
            .trim();
        if size_text.is_empty() {
            return Err(HttpError::InvalidChunkSize);
        }

        let chunk_size =
            usize::from_str_radix(size_text, 16).map_err(|_| HttpError::InvalidChunkSize)?;

        if chunk_size == 0 {
            consume_trailer_block(reader)?;
            return Ok(body);
        }

        let mut chunk = vec![0_u8; chunk_size];
        reader.read_exact(&mut chunk)?;
        body.extend_from_slice(&chunk);

        let mut terminator = [0_u8; 2];
        reader.read_exact(&mut terminator)?;
        if terminator != *b"\r\n" {
            return Err(HttpError::InvalidChunkTerminator);
        }
    }
}

fn consume_trailer_block<R: Read>(reader: &mut R) -> Result<(), HttpError> {
    loop {
        let line = read_crlf_line(reader)?.ok_or(HttpError::UnexpectedEof)?;
        if line.is_empty() {
            return Ok(());
        }
    }
}

fn read_connection_close_body<R: Read>(reader: &mut R) -> Result<Vec<u8>, HttpError> {
    let mut body = Vec::new();
    reader.read_to_end(&mut body)?;
    Ok(body)
}

/// Writes a buffered body using the provided framing strategy.
///
/// # Errors
///
/// Returns any I/O error from `writer`.
pub(crate) fn write_body<W: Write>(
    writer: &mut W,
    framing: &HttpBodyFraming,
    body: &[u8],
) -> io::Result<()> {
    match framing {
        HttpBodyFraming::None => Ok(()),
        HttpBodyFraming::ContentLength(_) | HttpBodyFraming::ConnectionClose => {
            writer.write_all(body)
        }
        HttpBodyFraming::Chunked => write_chunked_body(writer, body),
    }
}

fn write_chunked_body<W: Write>(writer: &mut W, body: &[u8]) -> io::Result<()> {
    if body.is_empty() {
        return writer.write_all(b"0\r\n\r\n");
    }

    write!(writer, "{:X}\r\n", body.len())?;
    writer.write_all(body)?;
    writer.write_all(b"\r\n0\r\n\r\n")
}
