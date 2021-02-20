//! Stub implementation of TLS API.
//!
//! All operations return error. No objects can be instantiated.
//!
//! Can be useful when you need a type parameter of type e. g. `TlsConnector`:
//!
//! ```
//! use tls_api_stub::TlsConnector;
//!
//! let no_connector: Option<TlsConnector> = None;
//! ```

#![deny(broken_intra_doc_links)]

use std::error;
use std::fmt;

mod stream;

mod acceptor;
mod connector;

pub use acceptor::TlsAcceptor;
pub use acceptor::TlsAcceptorBuilder;
pub use connector::TlsConnector;
pub use connector::TlsConnectorBuilder;
use tls_api::ImplInfo;

#[derive(Debug)]
struct Error;

impl error::Error for Error {
    fn description(&self) -> &str {
        "stub implementation"
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "stub implementation")
    }
}

pub(crate) fn info() -> ImplInfo {
    ImplInfo {
        name: "stub",
        version: "none",
    }
}
