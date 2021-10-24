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

#![deny(rustdoc::broken_intra_doc_links)]

pub use acceptor::TlsAcceptor;
pub use acceptor::TlsAcceptorBuilder;
pub use connector::TlsConnector;
pub use connector::TlsConnectorBuilder;
pub use stream::TlsStream;

use tls_api::ImplInfo;

mod stream;

mod acceptor;
mod connector;

#[derive(Debug, thiserror::Error)]
#[error("stub implementation")]
struct Error;

pub(crate) fn info() -> ImplInfo {
    ImplInfo {
        name: "stub",
        version: "none",
    }
}
