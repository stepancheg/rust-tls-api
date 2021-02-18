use crate::runtime::AsyncRead;
use crate::runtime::AsyncWrite;
use crate::TlsStream;
use std::fmt;
use std::future::Future;
use std::pin::Pin;

/// A builder for `TlsAcceptor`s.
pub trait TlsAcceptorBuilder: Sized + Sync + Send + 'static {
    type Acceptor: TlsAcceptor;

    // Type of underlying builder
    type Underlying;

    const SUPPORTS_ALPN: bool;

    fn set_alpn_protocols(&mut self, protocols: &[&[u8]]) -> crate::Result<()>;

    fn underlying_mut(&mut self) -> &mut Self::Underlying;

    fn build(self) -> crate::Result<Self::Acceptor>;
}

/// A builder for server-side TLS connections.
pub trait TlsAcceptor: Sized + Sync + Send + 'static {
    type Builder: TlsAcceptorBuilder<Acceptor = Self>;

    const SUPPORTS_ALPN: bool = <Self::Builder as TlsAcceptorBuilder>::SUPPORTS_ALPN;

    fn accept<'a, S>(
        &'a self,
        stream: S,
    ) -> Pin<Box<dyn Future<Output = crate::Result<TlsStream<S>>> + Send + 'a>>
    where
        S: AsyncRead + AsyncWrite + fmt::Debug + Unpin + Send + Sync + 'static;
}
