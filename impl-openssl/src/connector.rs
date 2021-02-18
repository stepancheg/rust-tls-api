use crate::encode_alpn_protos;
use crate::handshake::HandshakeFuture;
use crate::HAS_ALPN;
use std::fmt;
use tls_api::async_as_sync::AsyncIoAsSyncIo;
use tls_api::runtime::AsyncRead;
use tls_api::runtime::AsyncWrite;
use tls_api::BoxFuture;

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

    const SUPPORTS_ALPN: bool = HAS_ALPN;

    #[cfg(has_alpn)]
    fn set_alpn_protocols(&mut self, protocols: &[&[u8]]) -> tls_api::Result<()> {
        self.builder
            .set_alpn_protos(&encode_alpn_protos(protocols)?)
            .map_err(tls_api::Error::new)
    }

    #[cfg(not(has_alpn))]
    fn set_alpn_protocols(&mut self, _protocols: &[&[u8]]) -> tls_api::Result<()> {
        Err(tls_api::Error::new_other(
            "openssl is compiled without alpn",
        ))
    }

    fn set_verify_hostname(&mut self, verify: bool) -> tls_api::Result<()> {
        self.verify_hostname = verify;
        Ok(())
    }

    fn add_root_certificate(&mut self, cert: &tls_api::X509Cert) -> tls_api::Result<&mut Self> {
        let cert = openssl::x509::X509::from_der(cert.as_bytes()).map_err(tls_api::Error::new)?;

        self.builder
            .cert_store_mut()
            .add_cert(cert)
            .map_err(tls_api::Error::new)?;

        Ok(self)
    }

    fn build(self) -> tls_api::Result<TlsConnector> {
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

impl tls_api::TlsConnector for TlsConnector {
    type Builder = TlsConnectorBuilder;

    fn builder() -> tls_api::Result<TlsConnectorBuilder> {
        let builder = openssl::ssl::SslConnector::builder(openssl::ssl::SslMethod::tls())
            .map_err(tls_api::Error::new)?;
        Ok(TlsConnectorBuilder {
            builder,
            verify_hostname: true,
        })
    }

    fn connect<'a, S>(
        &'a self,
        domain: &'a str,
        stream: S,
    ) -> BoxFuture<'a, tls_api::Result<tls_api::TlsStream<S>>>
    where
        S: AsyncRead + AsyncWrite + fmt::Debug + Unpin + Send + Sync + 'static,
    {
        let client_configuration = match self.connector.configure() {
            Ok(client_configuration) => client_configuration,
            Err(e) => return BoxFuture::new(async { Err(tls_api::Error::new(e)) }),
        };
        let client_configuration = client_configuration.verify_hostname(self.verify_hostname);
        BoxFuture::new(HandshakeFuture::Initial(
            move |stream| client_configuration.connect(domain, stream),
            AsyncIoAsSyncIo::new(stream),
        ))
    }
}
