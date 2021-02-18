use crate::handshake::HandshakeFuture;
use rustls::NoClientAuth;
use rustls::StreamOwned;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use tls_api::async_as_sync::AsyncIoAsSyncIo;
use tls_api::runtime::AsyncRead;
use tls_api::runtime::AsyncWrite;
use tls_api::PrivateKey;
use tls_api::X509Cert;

pub struct TlsAcceptorBuilder(pub rustls::ServerConfig);
pub struct TlsAcceptor(pub Arc<rustls::ServerConfig>);

impl TlsAcceptorBuilder {
    pub fn from_cert_and_key(
        cert: &X509Cert,
        key: &PrivateKey,
    ) -> tls_api::Result<TlsAcceptorBuilder> {
        let mut config = rustls::ServerConfig::new(Arc::new(NoClientAuth));
        let cert = rustls::Certificate(cert.as_bytes().to_vec());
        config
            .set_single_cert(vec![cert], rustls::PrivateKey(key.as_bytes().to_vec()))
            .map_err(tls_api::Error::new)?;
        Ok(TlsAcceptorBuilder(config))
    }
}

impl tls_api::TlsAcceptorBuilder for TlsAcceptorBuilder {
    type Acceptor = TlsAcceptor;

    type Underlying = rustls::ServerConfig;

    // TODO: https://github.com/sfackler/rust-openssl/pull/646
    const SUPPORTS_ALPN: bool = true;

    fn set_alpn_protocols(&mut self, protocols: &[&[u8]]) -> tls_api::Result<()> {
        self.0.alpn_protocols = protocols.into_iter().map(|p| p.to_vec()).collect();
        Ok(())
    }

    fn underlying_mut(&mut self) -> &mut rustls::ServerConfig {
        &mut self.0
    }

    fn build(self) -> tls_api::Result<TlsAcceptor> {
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
        let tls_stream = crate::TlsStream {
            stream: StreamOwned {
                sock: AsyncIoAsSyncIo::new(stream),
                sess: rustls::ServerSession::new(&self.0),
            },
        };

        Box::pin(HandshakeFuture::MidHandshake(tls_stream))
    }
}
