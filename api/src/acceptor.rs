use crate::runtime::AsyncRead;
use crate::runtime::AsyncWrite;
use crate::stream_dyn::TlsStreamDyn;
use crate::BoxFuture;
use crate::Pkcs12AndPassword;
use crate::PrivateKey;
use crate::TlsStream;
use crate::X509Cert;
use std::fmt;
use std::future::Future;
use std::pin::Pin;

/// A builder for `TlsAcceptor`s.
pub trait TlsAcceptorBuilder: Sized + Sync + Send + 'static {
    type Acceptor: TlsAcceptor;

    // Type of underlying builder
    type Underlying;

    const SUPPORTS_ALPN: bool;

    const SUPPORTS_DER_KEYS: bool;
    const SUPPORTS_PKCS12_KEYS: bool;

    fn set_alpn_protocols(&mut self, protocols: &[&[u8]]) -> crate::Result<()>;

    fn underlying_mut(&mut self) -> &mut Self::Underlying;

    fn build(self) -> crate::Result<Self::Acceptor>;
}

/// A builder for server-side TLS connections.
pub trait TlsAcceptor: Sized + Sync + Send + 'static {
    type Builder: TlsAcceptorBuilder<Acceptor = Self>;

    const SUPPORTS_ALPN: bool = <Self::Builder as TlsAcceptorBuilder>::SUPPORTS_ALPN;

    fn builder_from_der_key(cert: &X509Cert, key: &PrivateKey) -> crate::Result<Self::Builder> {
        let _ = (cert, key);
        assert!(!Self::Builder::SUPPORTS_DER_KEYS);
        Err(crate::Error::new_other(
            "construction from DER key is not implemented",
        ))
    }

    fn builder_from_pkcs12(pkcs12: &Pkcs12AndPassword) -> crate::Result<Self::Builder> {
        let _ = pkcs12;
        assert!(!Self::Builder::SUPPORTS_PKCS12_KEYS);
        Err(crate::Error::new_other(
            "construction from PKCS12 is not implemented",
        ))
    }

    fn accept<'a, S>(
        &'a self,
        stream: S,
    ) -> Pin<Box<dyn Future<Output = crate::Result<TlsStream<S>>> + Send + 'a>>
    where
        S: AsyncRead + AsyncWrite + fmt::Debug + Unpin + Send + Sync + 'static;

    fn accept_dyn<'a, S>(&'a self, stream: S) -> BoxFuture<'a, crate::Result<TlsStreamDyn>>
    where
        S: AsyncRead + AsyncWrite + fmt::Debug + Unpin + Send + Sync + 'static,
    {
        BoxFuture::new(async move { self.accept(stream).await.map(TlsStreamDyn::new) })
    }
}
