use std::fmt;

use crate::handshake::HandshakeFuture;
use std::future::Future;
use std::pin::Pin;
use tls_api::async_as_sync::AsyncIoAsSyncIo;
use tls_api::runtime::AsyncRead;
use tls_api::runtime::AsyncWrite;
use tls_api::Error;
use tls_api::Pkcs12AndPassword;
use tls_api::Result;

mod handshake;
mod stream;

pub(crate) use stream::TlsStream;

pub struct TlsConnectorBuilder {
    pub builder: native_tls::TlsConnectorBuilder,
    pub verify_hostname: bool,
}

pub struct TlsConnector {
    pub connector: native_tls::TlsConnector,
    pub verify_hostname: bool,
}

pub struct TlsAcceptorBuilder(pub native_tls::TlsAcceptorBuilder);
pub struct TlsAcceptor(pub native_tls::TlsAcceptor);

impl tls_api::TlsConnectorBuilder for TlsConnectorBuilder {
    type Connector = TlsConnector;

    type Underlying = native_tls::TlsConnectorBuilder;

    fn underlying_mut(&mut self) -> &mut native_tls::TlsConnectorBuilder {
        &mut self.builder
    }

    const SUPPORTS_ALPN: bool = false;

    fn set_alpn_protocols(&mut self, _protocols: &[&[u8]]) -> Result<()> {
        Err(Error::new_other(
            "ALPN is not implemented in rust-native-tls",
        ))
    }

    fn set_verify_hostname(&mut self, verify: bool) -> Result<()> {
        self.builder.danger_accept_invalid_hostnames(!verify);
        self.verify_hostname = verify;
        Ok(())
    }

    fn add_root_certificate(&mut self, cert: &tls_api::X509Cert) -> Result<&mut Self> {
        let cert = native_tls::Certificate::from_der(cert.as_bytes()).map_err(Error::new)?;

        self.builder.add_root_certificate(cert);

        Ok(self)
    }

    fn build(self) -> Result<TlsConnector> {
        let connector = self.builder.build().map_err(Error::new)?;
        Ok(TlsConnector {
            connector,
            verify_hostname: self.verify_hostname,
        })
    }
}

impl tls_api::TlsConnector for TlsConnector {
    type Builder = TlsConnectorBuilder;

    fn builder() -> Result<TlsConnectorBuilder> {
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
    ) -> Pin<Box<dyn Future<Output = tls_api::Result<tls_api::TlsStream<S>>> + Send + 'a>>
    where
        S: AsyncRead + AsyncWrite + fmt::Debug + Unpin + Send + Sync + 'static,
    {
        Box::pin(HandshakeFuture::Initial(
            move |s| self.connector.connect(domain, s),
            AsyncIoAsSyncIo::new(stream),
        ))
    }
}

// TlsAcceptor and TlsAcceptorBuilder

impl TlsAcceptorBuilder {
    pub fn from_pkcs12(pkcs12: &Pkcs12AndPassword) -> Result<TlsAcceptorBuilder> {
        let pkcs12 = native_tls::Identity::from_pkcs12(&pkcs12.pkcs12.0, &pkcs12.password)
            .map_err(Error::new)?;

        Ok(native_tls::TlsAcceptor::builder(pkcs12)).map(TlsAcceptorBuilder)
    }
}

impl tls_api::TlsAcceptorBuilder for TlsAcceptorBuilder {
    type Acceptor = TlsAcceptor;

    type Underlying = native_tls::TlsAcceptorBuilder;

    const SUPPORTS_ALPN: bool = false;

    fn set_alpn_protocols(&mut self, _protocols: &[&[u8]]) -> Result<()> {
        Err(Error::new_other(
            "ALPN is not implemented in rust-native-tls",
        ))
    }

    fn underlying_mut(&mut self) -> &mut native_tls::TlsAcceptorBuilder {
        &mut self.0
    }

    fn build(self) -> Result<TlsAcceptor> {
        self.0.build().map(TlsAcceptor).map_err(Error::new)
    }
}

impl tls_api::TlsAcceptor for TlsAcceptor {
    type Builder = TlsAcceptorBuilder;

    fn accept<'a, S>(
        &'a self,
        stream: S,
    ) -> Pin<Box<dyn Future<Output = tls_api::Result<tls_api::TlsStream<S>>> + Send + 'a>>
    where
        S: AsyncRead + AsyncWrite + fmt::Debug + Unpin + Send + Sync + 'static,
    {
        Box::pin(HandshakeFuture::Initial(
            move |s| self.0.accept(s),
            AsyncIoAsSyncIo::new(stream),
        ))
    }
}
