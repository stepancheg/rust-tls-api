use std::future::Future;

use tls_api::spi_connector_common;
use tls_api::AsyncSocket;
use tls_api::AsyncSocketBox;
use tls_api::ImplInfo;

pub struct TlsConnectorBuilder(pub ());

impl tls_api::TlsConnectorBuilder for TlsConnectorBuilder {
    type Connector = TlsConnector;
    type Underlying = ();

    fn underlying_mut(&mut self) -> &mut Self::Underlying {
        &mut self.0
    }

    fn set_alpn_protocols(&mut self, protocols: &[&[u8]]) -> tls_api::Result<()> {
        let _ = protocols;
        Err(crate::Error::Alpn.into())
    }

    fn set_verify_hostname(&mut self, verify: bool) -> tls_api::Result<()> {
        let _ = verify;
        Ok(())
    }

    fn add_root_certificate(&mut self, cert: &[u8]) -> tls_api::Result<()> {
        let _ = cert;
        Ok(())
    }

    fn build(self) -> tls_api::Result<Self::Connector> {
        Ok(TlsConnector(self.0))
    }
}

pub struct TlsConnector(pub ());

impl TlsConnector {
    fn connect_impl<'a, S>(
        &'a self,
        domain: &'a str,
        stream: S,
    ) -> impl Future<Output = tls_api::Result<crate::TlsStream<S>>> + 'a
    where
        S: AsyncSocket,
    {
        let _ = domain;
        async { Ok(crate::stream::TlsStream(stream)) }
    }
}

impl tls_api::TlsConnector for TlsConnector {
    type Builder = TlsConnectorBuilder;

    const IMPLEMENTED: bool = false;
    const SUPPORTS_ALPN: bool = false;

    type Underlying = ();
    type TlsStream = crate::TlsStream<AsyncSocketBox>;

    fn underlying_mut(&mut self) -> &mut Self::Underlying {
        &mut self.0
    }

    fn info() -> ImplInfo {
        crate::info()
    }

    fn builder() -> tls_api::Result<TlsConnectorBuilder> {
        Ok(TlsConnectorBuilder(()))
    }

    spi_connector_common!();
}
