use std::future::Future;

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
        Ok(TlsAcceptor(self.0))
    }
}

pub struct TlsAcceptor(pub ());

impl TlsAcceptor {
    fn accept_impl<'a, S>(
        &'a self,
        stream: S,
    ) -> impl Future<Output = anyhow::Result<crate::TlsStream<S>>> + 'a
    where
        S: AsyncSocket + fmt::Debug + Unpin,
    {
        async { Ok(crate::stream::TlsStream(stream)) }
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

    spi_acceptor_common!();
}
