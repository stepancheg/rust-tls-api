use crate::handshake::HandshakeFuture;
use std::fmt;
use tls_api::async_as_sync::AsyncIoAsSyncIo;
use tls_api::runtime::AsyncRead;
use tls_api::runtime::AsyncWrite;
use tls_api::BoxFuture;

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

    const SUPPORTS_ALPN: bool = false;

    fn set_alpn_protocols(&mut self, _protocols: &[&[u8]]) -> tls_api::Result<()> {
        Err(tls_api::Error::new_other(
            "ALPN is not implemented in rust-native-tls",
        ))
    }

    fn set_verify_hostname(&mut self, verify: bool) -> tls_api::Result<()> {
        self.builder.danger_accept_invalid_hostnames(!verify);
        self.verify_hostname = verify;
        Ok(())
    }

    fn add_root_certificate(&mut self, cert: &tls_api::X509Cert) -> tls_api::Result<&mut Self> {
        let cert =
            native_tls::Certificate::from_der(cert.as_bytes()).map_err(tls_api::Error::new)?;

        self.builder.add_root_certificate(cert);

        Ok(self)
    }

    fn build(self) -> tls_api::Result<TlsConnector> {
        let connector = self.builder.build().map_err(tls_api::Error::new)?;
        Ok(TlsConnector {
            connector,
            verify_hostname: self.verify_hostname,
        })
    }
}

impl tls_api::TlsConnector for TlsConnector {
    type Builder = TlsConnectorBuilder;

    fn builder() -> tls_api::Result<TlsConnectorBuilder> {
        let builder = native_tls::TlsConnector::builder();
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
        BoxFuture::new(HandshakeFuture::Initial(
            move |s| self.connector.connect(domain, s),
            AsyncIoAsSyncIo::new(stream),
        ))
    }
}
