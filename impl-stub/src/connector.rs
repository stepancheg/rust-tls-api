use tls_api::spi_connector_common;
use tls_api::AsyncSocket;
use tls_api::AsyncSocketBox;
use tls_api::ImplInfo;

use void::Void;

use crate::Error;

/// Non-instantiatable.
pub struct TlsConnectorBuilder(Void);
/// Non-instantiatable.
pub struct TlsConnector(Void);

impl tls_api::TlsConnectorBuilder for TlsConnectorBuilder {
    type Connector = TlsConnector;

    type Underlying = Void;

    fn underlying_mut(&mut self) -> &mut Void {
        &mut self.0
    }

    fn set_alpn_protocols(&mut self, _protocols: &[&[u8]]) -> anyhow::Result<()> {
        Err(anyhow::Error::new(Error))
    }

    fn set_verify_hostname(&mut self, _verify: bool) -> anyhow::Result<()> {
        Err(anyhow::Error::new(Error))
    }

    fn add_root_certificate(&mut self, _cert: &[u8]) -> anyhow::Result<()> {
        Err(anyhow::Error::new(Error))
    }

    fn build(self) -> anyhow::Result<TlsConnector> {
        Err(anyhow::Error::new(Error))
    }
}

impl TlsConnector {
    async fn connect_impl<'a, S>(
        &'a self,
        _domain: &'a str,
        _stream: S,
    ) -> anyhow::Result<crate::TlsStream<S>>
    where
        S: AsyncSocket,
    {
        Err(anyhow::Error::new(Error))
    }
}

impl tls_api::TlsConnector for TlsConnector {
    type Builder = TlsConnectorBuilder;

    const IMPLEMENTED: bool = false;
    const SUPPORTS_ALPN: bool = false;

    type Underlying = Void;
    type TlsStream = crate::TlsStream<AsyncSocketBox>;

    fn underlying_mut(&mut self) -> &mut Self::Underlying {
        &mut self.0
    }

    fn info() -> ImplInfo {
        crate::info()
    }

    fn builder() -> anyhow::Result<TlsConnectorBuilder> {
        Err(anyhow::Error::new(Error))
    }

    spi_connector_common!(crate::TlsStream<S>);
}
