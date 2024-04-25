use std::convert::TryFrom;
use std::sync::Arc;

use rustls::StreamOwned;

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
    pub root_store: rustls::RootCertStore,
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

    fn set_alpn_protocols(&mut self, protocols: &[&[u8]]) -> anyhow::Result<()> {
        self.config.alpn_protocols = protocols.into_iter().map(|p: &&[u8]| p.to_vec()).collect();
        Ok(())
    }

    fn set_verify_hostname(&mut self, verify: bool) -> anyhow::Result<()> {
        if !verify {
            struct NoCertificateVerifier;

            impl rustls::client::ServerCertVerifier for NoCertificateVerifier {
                fn verify_server_cert(
                    &self,
                    _end_entity: &rustls::Certificate,
                    _intermediates: &[rustls::Certificate],
                    _server_name: &rustls::ServerName,
                    _scts: &mut dyn Iterator<Item = &[u8]>,
                    _ocsp_response: &[u8],
                    _now: std::time::SystemTime,
                ) -> Result<rustls::client::ServerCertVerified, rustls::Error> {
                    Ok(rustls::client::ServerCertVerified::assertion())
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

    fn add_root_certificate(&mut self, cert: &[u8]) -> anyhow::Result<()> {
        let cert = rustls::Certificate(cert.to_vec());
        self.root_store.add(&cert).map_err(anyhow::Error::new)?;
        Ok(())
    }

    fn build(self) -> anyhow::Result<TlsConnector> {
        let mut config = self.config;
        if !self.root_store.is_empty() {
            let mut new_config = rustls::ClientConfig::builder()
                .with_safe_defaults()
                .with_root_certificates(self.root_store)
                .with_no_client_auth();
            new_config.alpn_protocols = config.alpn_protocols;
            new_config.session_storage = config.session_storage;
            new_config.max_fragment_size = config.max_fragment_size;
            new_config.client_auth_cert_resolver = config.client_auth_cert_resolver;
            new_config.enable_tickets = config.enable_tickets;
            new_config.enable_sni = config.enable_sni;
            new_config.key_log = config.key_log;
            new_config.enable_early_data = config.enable_early_data;
            config = new_config;
        }
        Ok(TlsConnector {
            config: Arc::new(config),
        })
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
        let dns_name = rustls::ServerName::try_from(domain);
        let dns_name = match dns_name.map_err(|_| anyhow::Error::new(webpki::InvalidDnsNameError)) {
            Ok(dns_name) => dns_name,
            Err(e) => return BoxFuture::new(async { Err(e) }),
        };
        let conn = rustls::ClientConnection::new(self.config.clone(), dns_name);
        let conn = match conn.map_err(|e| anyhow::Error::new(e)) {
            Ok(conn) => conn,
            Err(e) => return BoxFuture::new(async { Err(e) }),
        };
        let tls_stream: crate::TlsStream<S> =
            crate::TlsStream::new(RustlsStream::Client(StreamOwned {
                conn,
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

    fn builder() -> anyhow::Result<TlsConnectorBuilder> {
        let mut roots = rustls::RootCertStore::empty();
        roots.add_server_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.iter().map(|ta| {
            rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
                ta.subject.as_ref(),
                ta.subject_public_key_info.as_ref(),
                ta.name_constraints.as_ref().map(|x| x.as_ref()),
            )
        }));
        let config = rustls::ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(roots)
            .with_no_client_auth();
        Ok(TlsConnectorBuilder {
            config,
            verify_hostname: true,
            root_store: rustls::RootCertStore::empty(),
        })
    }

    spi_connector_common!();
}
