use std::fmt;
use tls_api::spi_acceptor_common;
use tls_api::AsyncSocket;
use tls_api::AsyncSocketBox;
use tls_api::ImplInfo;

pub struct TlsAcceptorBuilder(pub ());

impl tls_api::TlsAcceptorBuilder for TlsAcceptorBuilder {
    type Acceptor = TlsAcceptor;
    type Underlying = ();

    fn set_alpn_protocols(&mut self, protocols: &[&[u8]]) -> anyhow::Result<()> {
        let _ = protocols;
        Err(crate::Error::Alpn.into())
    }

    fn underlying_mut(&mut self) -> &mut Self::Underlying {
        &mut self.0
    }

    fn build(self) -> anyhow::Result<TlsAcceptor> {
        Ok(TlsAcceptor(()))
    }
}

pub struct TlsAcceptor(pub ());

impl TlsAcceptor {
    async fn accept_impl<S>(&self, stream: S) -> anyhow::Result<crate::TlsStream<S>>
    where
        S: AsyncSocket + fmt::Debug + Unpin,
    {
        Ok(crate::stream::TlsStream(stream))
    }
}

impl tls_api::TlsAcceptor for TlsAcceptor {
    type Builder = TlsAcceptorBuilder;

    const IMPLEMENTED: bool = true;
    const SUPPORTS_ALPN: bool = false;
    const SUPPORTS_DER_KEYS: bool = false;
    const SUPPORTS_PKCS12_KEYS: bool = false;

    type Underlying = ();
    type TlsStream = crate::TlsStream<AsyncSocketBox>;

    fn underlying_mut(&mut self) -> &mut Self::Underlying {
        &mut self.0
    }

    fn info() -> ImplInfo {
        crate::info()
    }

    spi_acceptor_common!(crate::TlsStream<S>);
}
