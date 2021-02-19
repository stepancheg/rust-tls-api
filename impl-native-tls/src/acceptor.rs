use crate::handshake::HandshakeFuture;
use std::fmt;
use tls_api::async_as_sync::AsyncIoAsSyncIo;
use tls_api::runtime::AsyncRead;
use tls_api::runtime::AsyncWrite;
use tls_api::BoxFuture;
use tls_api::Pkcs12AndPassword;

pub struct TlsAcceptorBuilder(pub native_tls::TlsAcceptorBuilder);
pub struct TlsAcceptor(pub native_tls::TlsAcceptor);

// TlsAcceptor and TlsAcceptorBuilder

impl TlsAcceptorBuilder {
    pub fn from_pkcs12(pkcs12: &Pkcs12AndPassword) -> tls_api::Result<TlsAcceptorBuilder> {
        let pkcs12 = native_tls::Identity::from_pkcs12(&pkcs12.pkcs12.0, &pkcs12.password)
            .map_err(tls_api::Error::new)?;

        Ok(native_tls::TlsAcceptor::builder(pkcs12)).map(TlsAcceptorBuilder)
    }
}

impl tls_api::TlsAcceptorBuilder for TlsAcceptorBuilder {
    type Acceptor = TlsAcceptor;

    type Underlying = native_tls::TlsAcceptorBuilder;

    fn set_alpn_protocols(&mut self, _protocols: &[&[u8]]) -> tls_api::Result<()> {
        Err(tls_api::Error::new_other(
            "ALPN is not implemented in rust-native-tls",
        ))
    }

    fn underlying_mut(&mut self) -> &mut native_tls::TlsAcceptorBuilder {
        &mut self.0
    }

    fn build(self) -> tls_api::Result<TlsAcceptor> {
        self.0.build().map(TlsAcceptor).map_err(tls_api::Error::new)
    }
}

impl tls_api::TlsAcceptor for TlsAcceptor {
    type Builder = TlsAcceptorBuilder;

    const IMPLEMENTED: bool = true;
    const SUPPORTS_ALPN: bool = false;
    const SUPPORTS_DER_KEYS: bool = false;
    const SUPPORTS_PKCS12_KEYS: bool = true;

    fn builder_from_pkcs12(pkcs12: &Pkcs12AndPassword) -> tls_api::Result<Self::Builder> {
        Ok(TlsAcceptorBuilder(native_tls::TlsAcceptor::builder(
            native_tls::Identity::from_pkcs12(&pkcs12.pkcs12.0, &pkcs12.password)
                .map_err(tls_api::Error::new)?,
        )))
    }

    fn accept<'a, S>(&'a self, stream: S) -> BoxFuture<'a, tls_api::Result<tls_api::TlsStream<S>>>
    where
        S: AsyncRead + AsyncWrite + fmt::Debug + Unpin + Send + 'static,
    {
        BoxFuture::new(HandshakeFuture::Initial(
            move |s| self.0.accept(s),
            AsyncIoAsSyncIo::new(stream),
        ))
    }
}
