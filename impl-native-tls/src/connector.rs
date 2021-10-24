use std::str;

use crate::handshake::HandshakeFuture;

use std::future::Future;
use tls_api::async_as_sync::AsyncIoAsSyncIo;
use tls_api::spi_connector_common;
use tls_api::AsyncSocket;
use tls_api::AsyncSocketBox;
use tls_api::ImplInfo;

pub struct TlsConnectorBuilder {
    pub builder: native_tls::TlsConnectorBuilder,
    pub verify_hostname: bool,
}

pub struct TlsConnector {
    pub connector: native_tls::TlsConnector,
    pub verify_hostname: bool,
}

impl tls_api::TlsConnectorBuilder for TlsConnectorBuilder {
    type Connector = TlsConnector;

    type Underlying = native_tls::TlsConnectorBuilder;

    fn underlying_mut(&mut self) -> &mut native_tls::TlsConnectorBuilder {
        &mut self.builder
    }

    fn set_alpn_protocols(&mut self, protocols: &[&[u8]]) -> anyhow::Result<()> {
        let protocols: Vec<&str> = protocols
            .iter()
            .map(|p| str::from_utf8(p).map_err(|e| crate::Error::AlpnProtocolNotUtf8(e).into()))
            .collect::<anyhow::Result<_>>()?;
        self.builder.request_alpns(&protocols);
        Ok(())
    }

    fn set_verify_hostname(&mut self, verify: bool) -> anyhow::Result<()> {
        self.builder.danger_accept_invalid_hostnames(!verify);
        self.verify_hostname = verify;
        Ok(())
    }

    fn add_root_certificate(&mut self, cert: &[u8]) -> anyhow::Result<()> {
        let cert = native_tls::Certificate::from_der(cert).map_err(anyhow::Error::new)?;

        self.builder.add_root_certificate(cert);

        Ok(())
    }

    fn build(self) -> anyhow::Result<TlsConnector> {
        let connector = self.builder.build().map_err(anyhow::Error::new)?;
        Ok(TlsConnector {
            connector,
            verify_hostname: self.verify_hostname,
        })
    }
}

impl TlsConnector {
    pub fn connect_impl<'a, S>(
        &'a self,
        domain: &'a str,
        stream: S,
    ) -> impl Future<Output = anyhow::Result<crate::TlsStream<S>>> + 'a
    where
        S: AsyncSocket,
    {
        HandshakeFuture::Initial(
            move |s| self.connector.connect(domain, s),
            AsyncIoAsSyncIo::new(stream),
        )
    }
}

impl tls_api::TlsConnector for TlsConnector {
    type Builder = TlsConnectorBuilder;

    type Underlying = native_tls::TlsConnector;
    type TlsStream = crate::TlsStream<AsyncSocketBox>;

    fn underlying_mut(&mut self) -> &mut Self::Underlying {
        &mut self.connector
    }

    const IMPLEMENTED: bool = true;
    const SUPPORTS_ALPN: bool = true;

    fn info() -> ImplInfo {
        crate::info()
    }

    fn builder() -> anyhow::Result<TlsConnectorBuilder> {
        let builder = native_tls::TlsConnector::builder();
        Ok(TlsConnectorBuilder {
            builder,
            verify_hostname: true,
        })
    }

    spi_connector_common!();
}
