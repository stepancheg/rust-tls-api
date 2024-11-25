#[cfg(any(target_os = "macos", target_os = "ios"))]
use security_framework::certificate::SecCertificate;
#[cfg(any(target_os = "macos", target_os = "ios"))]
use security_framework::secure_transport::ClientBuilder;

use std::str;

use std::future::Future;
use tls_api::spi_connector_common;
use tls_api::AsyncSocket;
use tls_api::AsyncSocketBox;
use tls_api::ImplInfo;

#[cfg(not(any(target_os = "macos", target_os = "ios")))]
type ClientBuilder = void::Void;

pub struct TlsConnector(pub ClientBuilder);
pub struct TlsConnectorBuilder(pub ClientBuilder);

impl tls_api::TlsConnectorBuilder for TlsConnectorBuilder {
    type Connector = TlsConnector;
    type Underlying = ClientBuilder;

    fn underlying_mut(&mut self) -> &mut Self::Underlying {
        &mut self.0
    }

    fn set_alpn_protocols(&mut self, protocols: &[&[u8]]) -> anyhow::Result<()> {
        #[cfg(any(target_os = "macos", target_os = "ios"))]
        {
            let protocols: Vec<&str> = protocols
                .iter()
                .map(|p| {
                    str::from_utf8(p)
                        .map_err(|e| crate::Error::ReturnedAlpnProtocolIsNotUtf8(e).into())
                })
                .collect::<anyhow::Result<_>>()?;
            self.0.alpn_protocols(&protocols);
            Ok(())
        }
        #[cfg(not(any(target_os = "macos", target_os = "ios")))]
        {
            let _ = protocols;
            crate::not_ios_or_macos()
        }
    }

    fn set_verify_hostname(&mut self, verify: bool) -> anyhow::Result<()> {
        #[cfg(any(target_os = "macos", target_os = "ios"))]
        {
            self.0.danger_accept_invalid_hostnames(!verify);
            Ok(())
        }
        #[cfg(not(any(target_os = "macos", target_os = "ios")))]
        {
            let _ = verify;
            crate::not_ios_or_macos()
        }
    }

    fn add_root_certificate(&mut self, cert: &[u8]) -> anyhow::Result<()> {
        #[cfg(any(target_os = "macos", target_os = "ios"))]
        {
            let cert = SecCertificate::from_der(cert).map_err(anyhow::Error::new)?;
            // TODO: overrides, not adds: https://github.com/kornelski/rust-security-framework/pull/116
            self.0.anchor_certificates(&[cert]);
            Ok(())
        }
        #[cfg(not(any(target_os = "macos", target_os = "ios")))]
        {
            let _ = cert;
            crate::not_ios_or_macos()
        }
    }

    fn build(self) -> anyhow::Result<TlsConnector> {
        Ok(TlsConnector(self.0))
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
        #[cfg(any(target_os = "macos", target_os = "ios"))]
        {
            crate::handshake::new_slient_handshake(self, domain, stream)
        }
        #[cfg(not(any(target_os = "macos", target_os = "ios")))]
        {
            let _ = (domain, stream);
            async { crate::not_ios_or_macos() }
        }
    }
}

impl tls_api::TlsConnector for TlsConnector {
    type Builder = TlsConnectorBuilder;

    type Underlying = ClientBuilder;
    type TlsStream = crate::TlsStream<AsyncSocketBox>;

    fn underlying_mut(&mut self) -> &mut Self::Underlying {
        &mut self.0
    }

    const IMPLEMENTED: bool = crate::IMPLEMENTED;
    const SUPPORTS_ALPN: bool = true;

    fn info() -> ImplInfo {
        crate::info()
    }

    fn builder() -> anyhow::Result<TlsConnectorBuilder> {
        #[cfg(any(target_os = "macos", target_os = "ios"))]
        {
            Ok(TlsConnectorBuilder(ClientBuilder::new()))
        }
        #[cfg(not(any(target_os = "macos", target_os = "ios")))]
        {
            crate::not_ios_or_macos()
        }
    }

    spi_connector_common!(crate::TlsStream<S>);
}
