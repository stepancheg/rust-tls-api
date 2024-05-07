use std::convert::TryFrom;
use std::sync::Arc;

use rustls::StreamOwned;

use tls_api::async_as_sync::AsyncIoAsSyncIo;
use tls_api::spi_acceptor_common;
use tls_api::AsyncSocket;
use tls_api::AsyncSocketBox;
use tls_api::BoxFuture;
use tls_api::ImplInfo;

use crate::handshake::HandshakeFuture;
use crate::RustlsStream;
use std::future::Future;

pub struct TlsAcceptorBuilder(pub rustls::ServerConfig);
pub struct TlsAcceptor(pub Arc<rustls::ServerConfig>);

impl tls_api::TlsAcceptorBuilder for TlsAcceptorBuilder {
    type Acceptor = TlsAcceptor;

    type Underlying = rustls::ServerConfig;

    fn set_alpn_protocols(&mut self, protocols: &[&[u8]]) -> anyhow::Result<()> {
        self.0.alpn_protocols = protocols.into_iter().map(|p| p.to_vec()).collect();
        Ok(())
    }

    fn underlying_mut(&mut self) -> &mut rustls::ServerConfig {
        &mut self.0
    }

    fn build(self) -> anyhow::Result<TlsAcceptor> {
        Ok(TlsAcceptor(Arc::new(self.0)))
    }
}

impl TlsAcceptor {
    pub fn accept_impl<'a, S>(
        &'a self,
        stream: S,
    ) -> impl Future<Output = anyhow::Result<crate::TlsStream<S>>> + 'a
    where
        S: AsyncSocket,
    {
        let conn = rustls::ServerConnection::new(self.0.clone());
        let conn = match conn.map_err(|e| anyhow::Error::new(e)) {
            Ok(conn) => conn,
            Err(e) => return BoxFuture::new(async { Err(e) }),
        };
        let tls_stream: crate::TlsStream<S> =
            crate::TlsStream::new(RustlsStream::Server(StreamOwned {
                sock: AsyncIoAsSyncIo::new(stream),
                conn,
            }));

        BoxFuture::new(HandshakeFuture::MidHandshake(tls_stream))
    }
}

impl tls_api::TlsAcceptor for TlsAcceptor {
    type Builder = TlsAcceptorBuilder;

    type Underlying = Arc<rustls::ServerConfig>;
    type TlsStream = crate::TlsStream<AsyncSocketBox>;

    fn underlying_mut(&mut self) -> &mut Self::Underlying {
        &mut self.0
    }

    const IMPLEMENTED: bool = true;
    // TODO: https://github.com/sfackler/rust-openssl/pull/646
    const SUPPORTS_ALPN: bool = true;
    const SUPPORTS_DER_KEYS: bool = true;
    const SUPPORTS_PKCS12_KEYS: bool = false;

    fn info() -> ImplInfo {
        crate::info()
    }

    fn builder_from_der_key(cert: &[u8], key: &[u8]) -> anyhow::Result<TlsAcceptorBuilder> {
        let cert = rustls::pki_types::CertificateDer::from(cert.to_vec());
        let config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![cert],
                rustls::pki_types::PrivateKeyDer::try_from(key.to_vec())
                    .map_err(|x| anyhow::anyhow!(x))?,
            )
            .map_err(anyhow::Error::new)?;
        Ok(TlsAcceptorBuilder(config))
    }

    spi_acceptor_common!();
}
