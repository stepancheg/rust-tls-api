//! Implementation neutral TLS API.

use std::fmt;

pub mod async_as_sync;
pub mod runtime;

use runtime::AsyncRead;
use runtime::AsyncWrite;

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
mod stream;
mod stream_dyn;

pub use acceptor::TlsAcceptor;
pub use acceptor::TlsAcceptorBuilder;
pub use connector::TlsConnector;
pub use connector::TlsConnectorBuilder;
pub use error::Error;
pub use error::Result;
pub use future::BoxFuture;
pub use stream::TlsStream;
pub use stream::TlsStreamImpl;
pub use stream_dyn::TlsStreamDyn;

fn _check_kinds() {
    use std::net::TcpStream;

    fn assert_sync<T: Sync>() {}
    fn assert_send<T: Send>() {}
    fn assert_send_value<T: Send>(t: T) -> T {
        t
    }

    assert_sync::<Error>();
    assert_send::<Error>();
    assert_sync::<TlsStream<TcpStream>>();
    assert_send::<TlsStream<TcpStream>>();

    fn connect_future_is_send<C, S>(c: &C, s: S)
    where
        C: TlsConnector,
        S: AsyncRead + AsyncWrite + fmt::Debug + Unpin + Send + Sync + 'static,
    {
        let f = c.connect("dom", s);
        assert_send_value(f);
    }

    fn accept_future_is_send<A, S>(a: &A, s: S)
    where
        A: TlsAcceptor,
        S: AsyncRead + AsyncWrite + fmt::Debug + Unpin + Send + Sync + 'static,
    {
        let f = a.accept(s);
        assert_send_value(f);
    }
}
