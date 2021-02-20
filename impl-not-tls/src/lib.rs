//! Fake implementation of TLS API: returned streams are not TLS streams,
//! but fake socket streams.
//!
//! Use at your own risk.

#![deny(broken_intra_doc_links)]

mod acceptor;
mod connector;
mod stream;

pub use acceptor::TlsAcceptor;
pub use acceptor::TlsAcceptorBuilder;
pub use connector::TlsConnector;
pub use connector::TlsConnectorBuilder;

pub(crate) fn version() -> &'static str {
    "version"
}
