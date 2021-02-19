#![deny(broken_intra_doc_links)]

mod acceptor;
mod connector;
mod handshake;
mod stream;

pub use acceptor::TlsAcceptor;
pub use acceptor::TlsAcceptorBuilder;
pub use connector::TlsConnector;
pub use connector::TlsConnectorBuilder;

pub(crate) use stream::TlsStream;

pub(crate) fn version() -> &'static str {
    "unknown"
}
