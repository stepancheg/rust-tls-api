//! Implementation neutral TLS API.

#![deny(broken_intra_doc_links)]
#![deny(missing_docs)]

pub mod async_as_sync;
pub mod runtime;

mod cert;
pub use cert::pem_to_cert_key_pair;
pub use cert::Pkcs12;
pub use cert::Pkcs12AndPassword;
pub use cert::PrivateKey;
pub use cert::X509Cert;

mod acceptor;
mod connector;
mod error;
mod future;
mod socket;
mod socket_box;
mod stream;
mod stream_box;

pub use acceptor::TlsAcceptor;
pub use acceptor::TlsAcceptorBuilder;
pub use connector::TlsConnector;
pub use connector::TlsConnectorBuilder;
pub use error::Error;
pub use error::Result;
pub use future::BoxFuture;
pub use socket::AsyncSocket;
pub use socket_box::AsyncSocketBox;
pub use stream::TlsStream;
pub use stream_box::TlsStreamBox;

/// Interfaces needed by API implementor (like `tls-api-rustls`),
/// and not needed by the users of API.
pub mod spi {
    pub use crate::stream::TlsStreamImpl;
}

fn _check_kinds() {
    fn assert_sync<T: Sync>() {}
    fn assert_send<T: Send>() {}
    fn assert_send_value<T: Send>(t: T) -> T {
        t
    }

    assert_sync::<Error>();
    assert_send::<Error>();
    // assert_sync::<TlsStream<TcpStream>>();

    fn assert_tls_stream_send<S: AsyncSocket>() {
        assert_send::<TlsStream<S>>();
    }

    fn connect_future_is_send<C, S>(c: &C, s: S)
    where
        C: TlsConnector,
        S: AsyncSocket,
    {
        let f = c.connect("dom", s);
        assert_send_value(f);
    }

    fn accept_future_is_send<A, S>(a: &A, s: S)
    where
        A: TlsAcceptor,
        S: AsyncSocket,
    {
        let f = a.accept(s);
        assert_send_value(f);
    }
}
