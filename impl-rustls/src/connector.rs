use crate::handshake::HandshakeFuture;
use rustls::StreamOwned;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use tls_api::async_as_sync::AsyncIoAsSyncIo;
use tls_api::async_as_sync::TlsStreamOverSyncIo;
use tls_api::runtime::AsyncRead;
use tls_api::runtime::AsyncWrite;
use webpki::DNSNameRef;

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

    const SUPPORTS_ALPN: bool = true;

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
                return Err(tls_api::Error::new_other(
                    "cannot set_verify_hostname(true) after set_verify_hostname(false)",
                ));
            }
        }

        Ok(())
    }

    fn add_root_certificate(&mut self, cert: &tls_api::X509Cert) -> tls_api::Result<&mut Self> {
        let cert = rustls::Certificate(cert.as_bytes().to_vec());
        self.config
            .root_store
            .add(&cert)
            .map_err(|e| tls_api::Error::new_other(&format!("{:?}", e)))?;
        Ok(self)
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

impl tls_api::TlsConnector for TlsConnector {
    type Builder = TlsConnectorBuilder;

    fn builder() -> tls_api::Result<TlsConnectorBuilder> {
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
        let tls_stream: crate::TlsStream<S, _> = TlsStreamOverSyncIo::new(StreamOwned {
            sess: rustls::ClientSession::new(&self.config, dns_name),
            sock: AsyncIoAsSyncIo::new(stream),
        });

        Box::pin(HandshakeFuture::MidHandshake(tls_stream))
    }
}
