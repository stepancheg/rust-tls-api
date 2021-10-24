//! Fake implementation of TLS API: returned streams are not TLS streams,
//! but wrapped plain socket streams.
//!
//! Can be useful for tests or to measure the overhead of TLS.
//!
//! Use at your own risk.

#![deny(rustdoc::broken_intra_doc_links)]

mod acceptor;
mod connector;
mod error;
mod stream;

pub(crate) use error::Error;

pub use acceptor::TlsAcceptor;
pub use acceptor::TlsAcceptorBuilder;
pub use connector::TlsConnector;
pub use connector::TlsConnectorBuilder;
pub use stream::TlsStream;

use tls_api::ImplInfo;

pub(crate) fn info() -> ImplInfo {
    ImplInfo {
        name: "not-tls",
        version: "none",
    }
}
