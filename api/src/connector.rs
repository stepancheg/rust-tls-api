use crate::runtime::AsyncRead;
use crate::runtime::AsyncWrite;
use crate::TlsStream;
use crate::X509Cert;
use std::fmt;
use std::future::Future;
use std::pin::Pin;

/// A builder for `TlsConnector`s.
pub trait TlsConnectorBuilder: Sized + Sync + Send + 'static {
    type Connector: TlsConnector;

    type Underlying;

    fn underlying_mut(&mut self) -> &mut Self::Underlying;

    const SUPPORTS_ALPN: bool;

    fn set_alpn_protocols(&mut self, protocols: &[&[u8]]) -> crate::Result<()>;

    fn set_verify_hostname(&mut self, verify: bool) -> crate::Result<()>;

    fn add_root_certificate(&mut self, cert: &X509Cert) -> crate::Result<&mut Self>;

    fn build(self) -> crate::Result<Self::Connector>;
}

/// A builder for client-side TLS connections.
pub trait TlsConnector: Sized + Sync + Send + 'static {
    type Builder: TlsConnectorBuilder<Connector = Self>;

    const SUPPORTS_ALPN: bool = <Self::Builder as TlsConnectorBuilder>::SUPPORTS_ALPN;

    fn builder() -> crate::Result<Self::Builder>;

    fn connect<'a, S>(
        &'a self,
        domain: &'a str,
        stream: S,
    ) -> Pin<Box<dyn Future<Output = crate::Result<TlsStream<S>>> + Send + 'a>>
    where
        S: AsyncRead + AsyncWrite + fmt::Debug + Unpin + Send + Sync + 'static;
}
