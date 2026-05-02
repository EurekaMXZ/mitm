//! HTTP message views, parsing, serialization, and body state management.

mod adapter;
mod body;
mod message;
mod parser;

pub use adapter::{HttpAdapter, HttpAdapterReport};
pub use message::{
    HttpBodyFraming, HttpMessageView, HttpRequestView, HttpResponseView, HttpVersion, RawHeader,
};
pub use parser::{
    read_http_request, read_http_response, write_http_request, write_http_response, HttpError,
    RequestReadOutcome,
};
