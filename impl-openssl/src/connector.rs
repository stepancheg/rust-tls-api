use tls_api::async_as_sync::AsyncIoAsSyncIo;
use tls_api::spi_connector_common;
use tls_api::AsyncSocket;
use tls_api::AsyncSocketBox;
use tls_api::BoxFuture;
use tls_api::ImplInfo;

use crate::encode_alpn_protos;
use crate::handshake::HandshakeFuture;
use crate::HAS_ALPN;
use std::future::Future;

pub struct TlsConnectorBuilder {
    pub builder: openssl::ssl::SslConnectorBuilder,
    pub verify_hostname: bool,
}

pub struct TlsConnector {
    pub connector: openssl::ssl::SslConnector,
    pub verify_hostname: bool,
}

impl tls_api::TlsConnectorBuilder for TlsConnectorBuilder {
    type Connector = TlsConnector;

    type Underlying = openssl::ssl::SslConnectorBuilder;

    fn underlying_mut(&mut self) -> &mut openssl::ssl::SslConnectorBuilder {
        &mut self.builder
    }

    #[cfg(has_alpn)]
    fn set_alpn_protocols(&mut self, protocols: &[&[u8]]) -> anyhow::Result<()> {
        self.builder
            .set_alpn_protos(&encode_alpn_protos(protocols)?)
            .map_err(anyhow::Error::new)
    }

    #[cfg(not(has_alpn))]
    fn set_alpn_protocols(&mut self, _protocols: &[&[u8]]) -> anyhow::Result<()> {
        Err(crate::Error::CompiledWithoutAlpn.into())
    }

    fn set_verify_hostname(&mut self, verify: bool) -> anyhow::Result<()> {
        self.verify_hostname = verify;
        Ok(())
    }

    fn add_root_certificate(&mut self, cert: &[u8]) -> anyhow::Result<()> {
        let cert = openssl::x509::X509::from_der(cert).map_err(anyhow::Error::new)?;

        self.builder
            .cert_store_mut()
            .add_cert(cert)
            .map_err(anyhow::Error::new)?;

        Ok(())
    }

    fn build(self) -> anyhow::Result<TlsConnector> {
        Ok(TlsConnector {
            connector: self.builder.build(),
            verify_hostname: self.verify_hostname,
        })
    }
}

impl TlsConnectorBuilder {
    pub fn builder_mut(&mut self) -> &mut openssl::ssl::SslConnectorBuilder {
        &mut self.builder
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
        let client_configuration = match self.connector.configure() {
            Ok(client_configuration) => client_configuration,
            Err(e) => return BoxFuture::new(async { Err(anyhow::Error::new(e)) }),
        };
        let client_configuration = client_configuration.verify_hostname(self.verify_hostname);
        BoxFuture::new(HandshakeFuture::Initial(
            move |stream| client_configuration.connect(domain, stream),
            AsyncIoAsSyncIo::new(stream),
        ))
    }
}

impl tls_api::TlsConnector for TlsConnector {
    type Builder = TlsConnectorBuilder;

    type Underlying = openssl::ssl::SslConnector;
    type TlsStream = crate::TlsStream<AsyncSocketBox>;

    fn underlying_mut(&mut self) -> &mut Self::Underlying {
        &mut self.connector
    }

    const IMPLEMENTED: bool = true;
    const SUPPORTS_ALPN: bool = HAS_ALPN;

    fn info() -> ImplInfo {
        crate::into()
    }

    fn builder() -> anyhow::Result<TlsConnectorBuilder> {
        let builder = openssl::ssl::SslConnector::builder(openssl::ssl::SslMethod::tls())
            .map_err(anyhow::Error::new)?;
        Ok(TlsConnectorBuilder {
            builder,
            verify_hostname: true,
        })
    }

    spi_connector_common!();
}
