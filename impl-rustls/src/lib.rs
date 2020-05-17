use std::fmt;
use std::io;
use std::io::Read;
use std::io::Write;
use std::result;
use std::str;
use std::sync::Arc;

use crate::handshake::HandshakeFuture;
use rustls::NoClientAuth;
use std::future::Future;
use std::pin::Pin;
use std::task::Context;
use std::task::Poll;
use tls_api::async_as_sync::AsyncIoAsSyncIo;
use tls_api::async_as_sync::AsyncIoAsSyncIoWrapper;
use tls_api::Error;
use tls_api::Result;
use tokio::io::AsyncRead;
use tokio::io::AsyncWrite;
use webpki::DNSNameRef;

mod handshake;

pub struct TlsConnectorBuilder {
    pub config: rustls::ClientConfig,
    pub verify_hostname: bool,
}
pub struct TlsConnector {
    pub config: Arc<rustls::ClientConfig>,
}

pub struct TlsAcceptorBuilder(pub rustls::ServerConfig);
pub struct TlsAcceptor(pub Arc<rustls::ServerConfig>);

pub struct TlsStream<S, T>
where
    S: AsyncRead + AsyncWrite + fmt::Debug + Unpin + Send + 'static,
    T: rustls::Session + Unpin + 'static,
{
    stream: AsyncIoAsSyncIo<S>,
    session: T,
}

// TODO: do not require Sync from TlsStream
unsafe impl<S, T> Sync for TlsStream<S, T>
where
    S: AsyncRead + AsyncWrite + fmt::Debug + Unpin + Send + 'static,
    T: rustls::Session + Unpin + 'static,
{
}

// TlsStream

impl<S, T> fmt::Debug for TlsStream<S, T>
where
    S: AsyncRead + AsyncWrite + fmt::Debug + Unpin + Send + 'static,
    T: rustls::Session + Unpin + 'static,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("TlsStream")
            .field("stream", &self.stream)
            .field("session", &"...")
            .finish()
    }
}

impl<S, T> AsyncIoAsSyncIoWrapper<S> for TlsStream<S, T>
where
    S: AsyncRead + AsyncWrite + fmt::Debug + Unpin + Send + 'static,
    T: rustls::Session + Unpin + 'static,
{
    fn get_mut(&mut self) -> &mut AsyncIoAsSyncIo<S> {
        &mut self.stream
    }
}

impl<S, T> AsyncRead for TlsStream<S, T>
where
    S: AsyncRead + AsyncWrite + fmt::Debug + Unpin + Send + 'static,
    T: rustls::Session + Unpin + 'static,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        self.with_context_sync_to_async(cx, |stream| {
            rustls::Stream {
                sock: &mut stream.stream,
                sess: &mut stream.session,
            }
            .read(buf)
        })
    }
}

impl<S, T> AsyncWrite for TlsStream<S, T>
where
    S: AsyncRead + AsyncWrite + fmt::Debug + Unpin + Send + 'static,
    T: rustls::Session + Unpin + 'static,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.with_context_sync_to_async(cx, |stream| {
            rustls::Stream {
                sock: &mut stream.stream,
                sess: &mut stream.session,
            }
            .write(buf)
        })
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.with_context_sync_to_async(cx, |stream| {
            rustls::Stream {
                sock: &mut stream.stream,
                sess: &mut stream.session,
            }
            .flush()
        })
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_flush(cx)
    }
}

impl<S, T> tls_api::TlsStreamImpl<S> for TlsStream<S, T>
where
    S: AsyncRead + AsyncWrite + fmt::Debug + Unpin + Send + 'static,
    T: rustls::Session + Unpin + 'static,
{
    fn get_alpn_protocol(&self) -> Option<Vec<u8>> {
        self.session.get_alpn_protocol().map(Vec::from)
    }

    fn get_mut(&mut self) -> &mut S {
        self.stream.get_inner_mut()
    }

    fn get_ref(&self) -> &S {
        self.stream.get_inner_ref()
    }
}

impl tls_api::TlsConnectorBuilder for TlsConnectorBuilder {
    type Connector = TlsConnector;

    type Underlying = rustls::ClientConfig;

    fn underlying_mut(&mut self) -> &mut rustls::ClientConfig {
        &mut self.config
    }

    fn supports_alpn() -> bool {
        true
    }

    fn set_alpn_protocols(&mut self, protocols: &[&[u8]]) -> Result<()> {
        self.config.alpn_protocols = protocols.into_iter().map(|p: &&[u8]| p.to_vec()).collect();
        Ok(())
    }

    fn set_verify_hostname(&mut self, verify: bool) -> Result<()> {
        if !verify {
            struct NoCertificateVerifier;

            impl rustls::ServerCertVerifier for NoCertificateVerifier {
                fn verify_server_cert(
                    &self,
                    _roots: &rustls::RootCertStore,
                    _presented_certs: &[rustls::Certificate],
                    _dns_name: webpki::DNSNameRef,
                    _ocsp_response: &[u8],
                ) -> result::Result<rustls::ServerCertVerified, rustls::TLSError> {
                    Ok(rustls::ServerCertVerified::assertion())
                }
            }

            self.config
                .dangerous()
                .set_certificate_verifier(Arc::new(NoCertificateVerifier));
            self.verify_hostname = false;
        } else {
            if !self.verify_hostname {
                return Err(Error::new_other(
                    "cannot set_verify_hostname(true) after set_verify_hostname(false)",
                ));
            }
        }

        Ok(())
    }

    fn add_root_certificate(&mut self, cert: tls_api::Certificate) -> Result<&mut Self> {
        match cert.format {
            tls_api::CertificateFormat::PEM => {
                let cert = rustls::internal::pemfile::certs(&mut cert.bytes.as_slice())
                    .map_err(|e| Error::new_other(&format!("{:?}", e)))?;
                if !cert.is_empty() {
                    self.config
                        .root_store
                        .add(&cert[0])
                        .map_err(|e| Error::new_other(&format!("{:?}", e)))?;
                }
            }
            tls_api::CertificateFormat::DER => {
                let cert = rustls::Certificate(cert.bytes);
                self.config
                    .root_store
                    .add(&cert)
                    .map_err(|e| Error::new_other(&format!("{:?}", e)))?;
            }
        }
        Ok(self)
    }

    fn build(mut self) -> Result<TlsConnector> {
        if self.config.root_store.is_empty() {
            self.config
                .root_store
                .add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);
        }
        Ok(TlsConnector {
            config: Arc::new(self.config),
        })
    }
}

impl tls_api::TlsConnector for TlsConnector {
    type Builder = TlsConnectorBuilder;

    fn builder() -> Result<TlsConnectorBuilder> {
        Ok(TlsConnectorBuilder {
            config: rustls::ClientConfig::new(),
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
        let dns_name =
            match DNSNameRef::try_from_ascii_str(domain).map_err(|e| tls_api::Error::new(e)) {
                Ok(dns_name) => dns_name,
                Err(e) => return Box::pin(async { Err(e) }),
            };
        let tls_stream = TlsStream {
            stream: AsyncIoAsSyncIo::new(stream),
            session: rustls::ClientSession::new(&self.config, dns_name),
        };

        Box::pin(HandshakeFuture::MidHandshake(tls_stream))
    }
}

// TlsAcceptor and TlsAcceptorBuilder

impl TlsAcceptorBuilder {
    pub fn from_certs_and_key(certs: &[&[u8]], key: &[u8]) -> Result<TlsAcceptorBuilder> {
        let mut config = rustls::ServerConfig::new(Arc::new(NoClientAuth));
        let certs = certs
            .into_iter()
            .map(|c| rustls::Certificate(c.to_vec()))
            .collect();
        config
            .set_single_cert(certs, rustls::PrivateKey(key.to_vec()))
            .map_err(tls_api::Error::new)?;
        Ok(TlsAcceptorBuilder(config))
    }
}

impl tls_api::TlsAcceptorBuilder for TlsAcceptorBuilder {
    type Acceptor = TlsAcceptor;

    type Underlying = rustls::ServerConfig;

    fn supports_alpn() -> bool {
        // TODO: https://github.com/sfackler/rust-openssl/pull/646
        true
    }

    fn set_alpn_protocols(&mut self, protocols: &[&[u8]]) -> Result<()> {
        self.0.alpn_protocols = protocols.into_iter().map(|p| p.to_vec()).collect();
        Ok(())
    }

    fn underlying_mut(&mut self) -> &mut rustls::ServerConfig {
        &mut self.0
    }

    fn build(self) -> Result<TlsAcceptor> {
        Ok(TlsAcceptor(Arc::new(self.0)))
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
        let tls_stream = TlsStream {
            stream: AsyncIoAsSyncIo::new(stream),
            session: rustls::ServerSession::new(&self.0),
        };

        Box::pin(HandshakeFuture::MidHandshake(tls_stream))
    }
}
