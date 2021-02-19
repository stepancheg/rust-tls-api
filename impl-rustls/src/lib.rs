mod handshake;
mod stream;

mod acceptor;
mod connector;

pub use acceptor::TlsAcceptor;
pub use acceptor::TlsAcceptorBuilder;
pub use connector::TlsConnector;
pub use connector::TlsConnectorBuilder;

pub(crate) use stream::TlsStream;

pub(crate) fn version() -> &'static str {
    "unknown"
}
