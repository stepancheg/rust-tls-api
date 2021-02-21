use std::sync::Arc;

use rustls::StreamOwned;
use webpki::DNSNameRef;

use tls_api::async_as_sync::AsyncIoAsSyncIo;
use tls_api::spi_connector_common;
use tls_api::AsyncSocket;
use tls_api::AsyncSocketBox;
use tls_api::BoxFuture;
use tls_api::ImplInfo;

use crate::handshake::HandshakeFuture;
use crate::RustlsStream;
use std::future::Future;

pub struct TlsConnectorBuilder {
    pub config: rustls::ClientConfig,
    pub verify_hostname: bool,
}
pub struct TlsConnector {
    pub config: Arc<rustls::ClientConfig>,
}

impl tls_api::TlsConnectorBuilder for TlsConnectorBuilder {
    type Connector = TlsConnector;

    type Underlying = rustls::ClientConfig;

    fn underlying_mut(&mut self) -> &mut rustls::ClientConfig {
        &mut self.config
    }

    fn set_alpn_protocols(&mut self, protocols: &[&[u8]]) -> tls_api::Result<()> {
        self.config.alpn_protocols = protocols.into_iter().map(|p: &&[u8]| p.to_vec()).collect();
        Ok(())
    }

    fn set_verify_hostname(&mut self, verify: bool) -> tls_api::Result<()> {
        if !verify {
            struct NoCertificateVerifier;

            impl rustls::ServerCertVerifier for NoCertificateVerifier {
                fn verify_server_cert(
                    &self,
                    _roots: &rustls::RootCertStore,
                    _presented_certs: &[rustls::Certificate],
                    _dns_name: webpki::DNSNameRef,
                    _ocsp_response: &[u8],
                ) -> Result<rustls::ServerCertVerified, rustls::TLSError> {
                    Ok(rustls::ServerCertVerified::assertion())
                }
            }

            self.config
                .dangerous()
                .set_certificate_verifier(Arc::new(NoCertificateVerifier));
            self.verify_hostname = false;
        } else {
            if !self.verify_hostname {
                return Err(crate::Error::VerifyHostnameTrue.into());
            }
        }

        Ok(())
    }

    fn add_root_certificate(&mut self, cert: &[u8]) -> tls_api::Result<()> {
        let cert = rustls::Certificate(cert.to_vec());
        self.config
            .root_store
            .add(&cert)
            .map_err(tls_api::Error::new)?;
        Ok(())
    }

    fn build(mut self) -> tls_api::Result<TlsConnector> {
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

impl TlsConnector {
    pub fn connect_impl<'a, S>(
        &'a self,
        domain: &'a str,
        stream: S,
    ) -> impl Future<Output = tls_api::Result<crate::TlsStream<S>>> + 'a
    where
        S: AsyncSocket,
    {
        let dns_name =
            match DNSNameRef::try_from_ascii_str(domain).map_err(|e| tls_api::Error::new(e)) {
                Ok(dns_name) => dns_name,
                Err(e) => return BoxFuture::new(async { Err(e) }),
            };
        let tls_stream: crate::TlsStream<S> =
            crate::TlsStream::new(RustlsStream::Client(StreamOwned {
                sess: rustls::ClientSession::new(&self.config, dns_name),
                sock: AsyncIoAsSyncIo::new(stream),
            }));

        BoxFuture::new(HandshakeFuture::MidHandshake(tls_stream))
    }
}

impl tls_api::TlsConnector for TlsConnector {
    type Builder = TlsConnectorBuilder;

    type Underlying = Arc<rustls::ClientConfig>;
    type TlsStream = crate::TlsStream<AsyncSocketBox>;

    fn underlying_mut(&mut self) -> &mut Self::Underlying {
        &mut self.config
    }

    const IMPLEMENTED: bool = true;
    const SUPPORTS_ALPN: bool = true;

    fn info() -> ImplInfo {
        crate::info()
    }

    fn builder() -> tls_api::Result<TlsConnectorBuilder> {
        Ok(TlsConnectorBuilder {
            config: rustls::ClientConfig::new(),
            verify_hostname: true,
        })
    }

    spi_connector_common!();
}
