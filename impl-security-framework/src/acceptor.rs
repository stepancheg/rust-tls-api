use std::future::Future;

#[cfg(any(target_os = "macos", target_os = "ios"))]
use security_framework::certificate::SecCertificate;
#[cfg(any(target_os = "macos", target_os = "ios"))]
use security_framework::identity::SecIdentity;
#[cfg(any(target_os = "macos", target_os = "ios"))]
use security_framework::import_export::Pkcs12ImportOptions;

use tls_api::spi_acceptor_common;
use tls_api::AsyncSocket;
use tls_api::AsyncSocketBox;
use tls_api::ImplInfo;

/// To be replaced with [`security_framework::secure_transport::ServerBuilder`]
/// in the next version of the `security_framework`.
#[cfg(any(target_os = "macos", target_os = "ios"))]
pub struct SecureTransportTlsAcceptorBuilder {
    pub identity: SecIdentity,
    pub certs: Vec<SecCertificate>,
}

/// To be replaced with `security_framework::secure_transport::ServerBuilder`
/// in the next version of the `security_framework`.
#[cfg(not(any(target_os = "macos", target_os = "ios")))]
pub type SecureTransportTlsAcceptorBuilder = void::Void;

pub struct TlsAcceptor(pub SecureTransportTlsAcceptorBuilder);
pub struct TlsAcceptorBuilder(pub SecureTransportTlsAcceptorBuilder);

impl tls_api::TlsAcceptorBuilder for TlsAcceptorBuilder {
    type Acceptor = TlsAcceptor;
    type Underlying = SecureTransportTlsAcceptorBuilder;

    fn set_alpn_protocols(&mut self, _protocols: &[&[u8]]) -> anyhow::Result<()> {
        Err(crate::Error::AlpnOnServer.into())
    }

    fn underlying_mut(&mut self) -> &mut Self::Underlying {
        &mut self.0
    }

    fn build(self) -> anyhow::Result<Self::Acceptor> {
        Ok(TlsAcceptor(self.0))
    }
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
fn pkcs12_to_sf_objects(
    pkcs12: &[u8],
    passphrase: &str,
) -> anyhow::Result<(SecIdentity, Vec<SecCertificate>)> {
    let imported_identities = Pkcs12ImportOptions::new()
        .passphrase(passphrase)
        .import(pkcs12)
        .map_err(anyhow::Error::new)?;
    let mut identities: Vec<(SecIdentity, Vec<SecCertificate>)> = imported_identities
        .into_iter()
        .flat_map(|i| {
            let cert_chain = i.cert_chain;
            i.identity.map(|i| (i, cert_chain.unwrap_or(Vec::new())))
        })
        .collect();
    if identities.len() == 0 {
        Err(crate::Error::IdentitiesNotFoundInPkcs12.into())
    } else if identities.len() == 1 {
        Ok(identities.pop().unwrap())
    } else {
        Err(crate::Error::MoreThanOneIdentityInPkcs12(identities.len() as _).into())
    }
}

impl TlsAcceptor {
    fn accept_impl<S>(
        &self,
        stream: S,
    ) -> impl Future<Output = anyhow::Result<crate::TlsStream<S>>> + '_
    where
        S: AsyncSocket,
    {
        #[cfg(any(target_os = "macos", target_os = "ios"))]
        {
            crate::handshake::new_server_handshake(self, stream)
        }
        #[cfg(not(any(target_os = "macos", target_os = "ios")))]
        {
            let _ = stream;
            async { crate::not_ios_or_macos() }
        }
    }
}

impl tls_api::TlsAcceptor for TlsAcceptor {
    type Builder = TlsAcceptorBuilder;

    type Underlying = SecureTransportTlsAcceptorBuilder;
    type TlsStream = crate::TlsStream<AsyncSocketBox>;

    fn underlying_mut(&mut self) -> &mut Self::Underlying {
        &mut self.0
    }

    const IMPLEMENTED: bool = crate::IMPLEMENTED;
    const SUPPORTS_ALPN: bool = false;
    const SUPPORTS_DER_KEYS: bool = false;
    const SUPPORTS_PKCS12_KEYS: bool = true;

    fn info() -> ImplInfo {
        crate::info()
    }

    fn builder_from_pkcs12(pkcs12: &[u8], passphrase: &str) -> anyhow::Result<TlsAcceptorBuilder> {
        #[cfg(any(target_os = "macos", target_os = "ios"))]
        {
            let (identity, certs) = pkcs12_to_sf_objects(pkcs12, passphrase)?;
            Ok(TlsAcceptorBuilder(SecureTransportTlsAcceptorBuilder {
                identity,
                certs,
            }))
        }
        #[cfg(not(any(target_os = "macos", target_os = "ios")))]
        {
            let _ = (pkcs12, passphrase);
            crate::not_ios_or_macos()
        }
    }

    spi_acceptor_common!(crate::TlsStream<S>);
}
