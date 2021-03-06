use crate::handshake::HandshakeFuture;

use std::future::Future;
use tls_api::async_as_sync::AsyncIoAsSyncIo;
use tls_api::spi_acceptor_common;
use tls_api::AsyncSocket;
use tls_api::AsyncSocketBox;
use tls_api::ImplInfo;

pub struct TlsAcceptorBuilder(pub native_tls::TlsAcceptorBuilder);
pub struct TlsAcceptor(pub native_tls::TlsAcceptor);

// TlsAcceptor and TlsAcceptorBuilder

impl tls_api::TlsAcceptorBuilder for TlsAcceptorBuilder {
    type Acceptor = TlsAcceptor;

    type Underlying = native_tls::TlsAcceptorBuilder;

    fn set_alpn_protocols(&mut self, _protocols: &[&[u8]]) -> tls_api::Result<()> {
        Err(crate::Error::AlpnNotSupported.into())
    }

    fn underlying_mut(&mut self) -> &mut native_tls::TlsAcceptorBuilder {
        &mut self.0
    }

    fn build(self) -> tls_api::Result<TlsAcceptor> {
        self.0.build().map(TlsAcceptor).map_err(tls_api::Error::new)
    }
}

impl TlsAcceptor {
    fn accept_impl<'a, S>(
        &'a self,
        stream: S,
    ) -> impl Future<Output = tls_api::Result<crate::TlsStream<S>>> + 'a
    where
        S: AsyncSocket,
    {
        HandshakeFuture::Initial(move |s| self.0.accept(s), AsyncIoAsSyncIo::new(stream))
    }
}

impl tls_api::TlsAcceptor for TlsAcceptor {
    type Builder = TlsAcceptorBuilder;

    type Underlying = native_tls::TlsAcceptor;
    type TlsStream = crate::TlsStream<AsyncSocketBox>;

    fn underlying_mut(&mut self) -> &mut Self::Underlying {
        &mut self.0
    }

    const IMPLEMENTED: bool = true;
    /// Server side of `native-tls` does not support ALPN,
    /// because `security-framework` does not support it.
    const SUPPORTS_ALPN: bool = false;
    const SUPPORTS_DER_KEYS: bool = false;
    const SUPPORTS_PKCS12_KEYS: bool = true;

    fn info() -> ImplInfo {
        crate::info()
    }

    fn builder_from_pkcs12(pkcs12: &[u8], passphrase: &str) -> tls_api::Result<Self::Builder> {
        Ok(TlsAcceptorBuilder(native_tls::TlsAcceptor::builder(
            native_tls::Identity::from_pkcs12(pkcs12, passphrase).map_err(tls_api::Error::new)?,
        )))
    }

    spi_acceptor_common!();
}
