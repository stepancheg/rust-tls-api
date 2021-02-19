use crate::runtime::AsyncRead;
use crate::runtime::AsyncWrite;
use crate::stream_box::TlsStreamBox;
use crate::BoxFuture;
use crate::Pkcs12AndPassword;
use crate::PrivateKey;
use crate::TlsStream;
use crate::X509Cert;
use std::fmt;

/// A builder for `TlsAcceptor`s.
pub trait TlsAcceptorBuilder: Sized + Sync + Send + 'static {
    type Acceptor: TlsAcceptor;

    // Type of underlying builder
    type Underlying;

    fn set_alpn_protocols(&mut self, protocols: &[&[u8]]) -> crate::Result<()>;

    fn underlying_mut(&mut self) -> &mut Self::Underlying;

    fn build(self) -> crate::Result<Self::Acceptor>;
}

/// A builder for server-side TLS connections.
pub trait TlsAcceptor: Sized + Sync + Send + 'static {
    type Builder: TlsAcceptorBuilder<Acceptor = Self>;

    const IMPLEMENTED: bool;
    const SUPPORTS_ALPN: bool;
    const SUPPORTS_DER_KEYS: bool;
    const SUPPORTS_PKCS12_KEYS: bool;

    fn builder_from_der_key(cert: &X509Cert, key: &PrivateKey) -> crate::Result<Self::Builder> {
        let _ = (cert, key);
        assert!(!Self::SUPPORTS_DER_KEYS);
        Err(crate::Error::new_other(
            "construction from DER key is not implemented",
        ))
    }

    fn builder_from_pkcs12(pkcs12: &Pkcs12AndPassword) -> crate::Result<Self::Builder> {
        let _ = pkcs12;
        assert!(!Self::SUPPORTS_PKCS12_KEYS);
        Err(crate::Error::new_other(
            "construction from PKCS12 is not implemented",
        ))
    }

    fn accept<'a, S>(&'a self, stream: S) -> BoxFuture<'a, crate::Result<TlsStream<S>>>
    where
        S: AsyncRead + AsyncWrite + fmt::Debug + Unpin + Send + 'static;

    fn accept_dyn<'a, S>(&'a self, stream: S) -> BoxFuture<'a, crate::Result<TlsStreamBox>>
    where
        S: AsyncRead + AsyncWrite + fmt::Debug + Unpin + Send + 'static,
    {
        BoxFuture::new(async move { self.accept(stream).await.map(TlsStreamBox::new) })
    }
}
