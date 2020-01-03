extern crate native_tls;
extern crate tls_api;

use std::fmt;
use std::io;

use crate::handshake::HandshakeFuture;
use std::future::Future;
use std::io::Read;
use std::io::Write;
use std::pin::Pin;
use std::task::Context;
use std::task::Poll;
use tls_api::async_as_sync::AsyncIoAsSyncIo;
use tls_api::async_as_sync::AsyncIoAsSyncIoWrapper;
use tls_api::Error;
use tls_api::Result;
use tokio::io::AsyncRead;
use tokio::io::AsyncWrite;

mod handshake;

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

    fn supports_alpn() -> bool {
        false
    }

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

    fn add_root_certificate(&mut self, cert: tls_api::Certificate) -> Result<&mut Self> {
        let cert = match cert.format {
            tls_api::CertificateFormat::DER => {
                native_tls::Certificate::from_der(&cert.bytes).map_err(Error::new)?
            }
            tls_api::CertificateFormat::PEM => {
                native_tls::Certificate::from_pem(&cert.bytes).map_err(Error::new)?
            }
        };

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

#[derive(Debug)]
struct TlsStream<S: AsyncRead + AsyncWrite + fmt::Debug + Unpin>(
    native_tls::TlsStream<AsyncIoAsSyncIo<S>>,
);

impl<S: Unpin + fmt::Debug + AsyncRead + AsyncWrite + Unpin + Sync + Send> AsyncIoAsSyncIoWrapper<S>
    for TlsStream<S>
{
    fn get_mut(&mut self) -> &mut AsyncIoAsSyncIo<S> {
        self.0.get_mut()
    }
}

impl<S: Unpin + fmt::Debug + AsyncRead + AsyncWrite + Sync + Send> AsyncWrite for TlsStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.get_mut()
            .with_context_sync_to_async(cx, |stream| stream.0.write(buf))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut()
            .with_context_sync_to_async(cx, |stream| stream.0.flush())
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut()
            .with_context_sync_to_async(cx, |stream| stream.0.shutdown())
    }
}

impl<S: Unpin + fmt::Debug + AsyncRead + AsyncWrite + Sync + Send> AsyncRead for TlsStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        self.get_mut()
            .with_context_sync_to_async(cx, |stream| stream.0.read(buf))
    }
}

impl<S: Unpin + fmt::Debug + AsyncRead + AsyncWrite + Sync + Send + 'static>
    tls_api::TlsStreamImpl<S> for TlsStream<S>
{
    fn get_alpn_protocol(&self) -> Option<Vec<u8>> {
        None
    }

    fn get_mut(&mut self) -> &mut S {
        self.0.get_mut().get_inner_mut()
    }

    fn get_ref(&self) -> &S {
        self.0.get_ref().get_inner_ref()
    }
}

struct MidHandshakeTlsStream<S: Unpin + fmt::Debug + AsyncRead + AsyncWrite + Sync + Send + 'static>(
    Option<native_tls::MidHandshakeTlsStream<S>>,
);

impl<S: Unpin + fmt::Debug + AsyncRead + AsyncWrite + Sync + Send + 'static> fmt::Debug
    for MidHandshakeTlsStream<S>
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("MidHandshakeTlsStream").finish()
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
    pub fn from_pkcs12(pkcs12: &[u8], password: &str) -> Result<TlsAcceptorBuilder> {
        let pkcs12 = native_tls::Identity::from_pkcs12(pkcs12, password).map_err(Error::new)?;

        Ok(native_tls::TlsAcceptor::builder(pkcs12)).map(TlsAcceptorBuilder)
    }
}

impl tls_api::TlsAcceptorBuilder for TlsAcceptorBuilder {
    type Acceptor = TlsAcceptor;

    type Underlying = native_tls::TlsAcceptorBuilder;

    fn supports_alpn() -> bool {
        false
    }

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
