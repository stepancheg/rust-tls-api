//! Implementation neutral TLS API.

use std::fmt;
use std::future::Future;
use std::pin::Pin;

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

mod error;
mod stream;

pub use error::Error;
pub use error::Result;
pub use stream::TlsStream;
pub use stream::TlsStreamImpl;

/// A builder for `TlsConnector`s.
pub trait TlsConnectorBuilder: Sized + Sync + Send + 'static {
    type Connector: TlsConnector;

    type Underlying;

    fn underlying_mut(&mut self) -> &mut Self::Underlying;

    const SUPPORTS_ALPN: bool;

    fn set_alpn_protocols(&mut self, protocols: &[&[u8]]) -> Result<()>;

    fn set_verify_hostname(&mut self, verify: bool) -> Result<()>;

    fn add_root_certificate(&mut self, cert: &X509Cert) -> Result<&mut Self>;

    fn build(self) -> Result<Self::Connector>;
}

/// A builder for client-side TLS connections.
pub trait TlsConnector: Sized + Sync + Send + 'static {
    type Builder: TlsConnectorBuilder<Connector = Self>;

    const SUPPORTS_ALPN: bool = <Self::Builder as TlsConnectorBuilder>::SUPPORTS_ALPN;

    fn builder() -> Result<Self::Builder>;

    fn connect<'a, S>(
        &'a self,
        domain: &'a str,
        stream: S,
    ) -> Pin<Box<dyn Future<Output = Result<TlsStream<S>>> + Send + 'a>>
    where
        S: AsyncRead + AsyncWrite + fmt::Debug + Unpin + Send + Sync + 'static;
}

/// A builder for `TlsAcceptor`s.
pub trait TlsAcceptorBuilder: Sized + Sync + Send + 'static {
    type Acceptor: TlsAcceptor;

    // Type of underlying builder
    type Underlying;

    const SUPPORTS_ALPN: bool;

    fn set_alpn_protocols(&mut self, protocols: &[&[u8]]) -> Result<()>;

    fn underlying_mut(&mut self) -> &mut Self::Underlying;

    fn build(self) -> Result<Self::Acceptor>;
}

/// A builder for server-side TLS connections.
pub trait TlsAcceptor: Sized + Sync + Send + 'static {
    type Builder: TlsAcceptorBuilder<Acceptor = Self>;

    const SUPPORTS_ALPN: bool = <Self::Builder as TlsAcceptorBuilder>::SUPPORTS_ALPN;

    fn accept<'a, S>(
        &'a self,
        stream: S,
    ) -> Pin<Box<dyn Future<Output = Result<TlsStream<S>>> + Send + 'a>>
    where
        S: AsyncRead + AsyncWrite + fmt::Debug + Unpin + Send + Sync + 'static;
}

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
