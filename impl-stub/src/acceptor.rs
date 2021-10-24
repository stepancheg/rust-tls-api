use void::Void;

use tls_api::spi_acceptor_common;
use tls_api::AsyncSocket;
use tls_api::AsyncSocketBox;
use tls_api::ImplInfo;

use crate::Error;
use std::future::Future;

/// Non-instantiatable.
pub struct TlsAcceptorBuilder(Void);
/// Non-instantiatable.
pub struct TlsAcceptor(Void);

impl tls_api::TlsAcceptorBuilder for TlsAcceptorBuilder {
    type Acceptor = TlsAcceptor;

    type Underlying = Void;

    fn set_alpn_protocols(&mut self, _protocols: &[&[u8]]) -> anyhow::Result<()> {
        Err(anyhow::Error::new(Error))
    }

    fn underlying_mut(&mut self) -> &mut Void {
        &mut self.0
    }

    fn build(self) -> anyhow::Result<TlsAcceptor> {
        Err(anyhow::Error::new(Error))
    }
}

impl TlsAcceptor {
    fn accept_impl<'a, S>(
        &'a self,
        _stream: S,
    ) -> impl Future<Output = anyhow::Result<crate::TlsStream<S>>> + 'a
    where
        S: AsyncSocket,
    {
        async { Err(anyhow::Error::new(Error)) }
    }
}

impl tls_api::TlsAcceptor for TlsAcceptor {
    type Builder = TlsAcceptorBuilder;

    const IMPLEMENTED: bool = false;
    const SUPPORTS_ALPN: bool = false;
    const SUPPORTS_DER_KEYS: bool = false;
    const SUPPORTS_PKCS12_KEYS: bool = false;

    type Underlying = Void;
    type TlsStream = crate::TlsStream<AsyncSocketBox>;

    fn underlying_mut(&mut self) -> &mut Self::Underlying {
        &mut self.0
    }

    fn info() -> ImplInfo {
        crate::info()
    }

    spi_acceptor_common!();
}
