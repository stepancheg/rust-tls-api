#[cfg(any(target_os = "macos", target_os = "ios"))]
use security_framework::certificate::SecCertificate;
#[cfg(any(target_os = "macos", target_os = "ios"))]
use security_framework::identity::SecIdentity;
#[cfg(any(target_os = "macos", target_os = "ios"))]
use security_framework::import_export::Pkcs12ImportOptions;

use tls_api::AsyncSocket;
use tls_api::BoxFuture;
use tls_api::ImplInfo;

#[cfg(any(target_os = "macos", target_os = "ios"))]
pub struct SecureTransportTlsAcceptorBuilder {
    pub identity: SecIdentity,
    pub certs: Vec<SecCertificate>,
}

#[cfg(not(any(target_os = "macos", target_os = "ios")))]
pub type SecureTransportTlsAcceptorBuilder = void::Void;

pub struct TlsAcceptor(pub SecureTransportTlsAcceptorBuilder);
pub struct TlsAcceptorBuilder(pub SecureTransportTlsAcceptorBuilder);

impl tls_api::TlsAcceptorBuilder for TlsAcceptorBuilder {
    type Acceptor = TlsAcceptor;
    type Underlying = SecureTransportTlsAcceptorBuilder;

    fn set_alpn_protocols(&mut self, _protocols: &[&[u8]]) -> tls_api::Result<()> {
        Err(crate::Error::AlpnOnServer.into())
    }

    fn underlying_mut(&mut self) -> &mut Self::Underlying {
        &mut self.0
    }

    fn build(self) -> tls_api::Result<Self::Acceptor> {
        Ok(TlsAcceptor(self.0))
    }
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
fn pkcs12_to_sf_objects(
    pkcs12: &[u8],
    passphrase: &str,
) -> tls_api::Result<(SecIdentity, Vec<SecCertificate>)> {
    let imported_identities = Pkcs12ImportOptions::new()
        .passphrase(passphrase)
        .import(pkcs12)
        .map_err(tls_api::Error::new)?;
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

impl tls_api::TlsAcceptor for TlsAcceptor {
    type Builder = TlsAcceptorBuilder;

    type Underlying = SecureTransportTlsAcceptorBuilder;

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

    fn builder_from_pkcs12(pkcs12: &[u8], passphrase: &str) -> tls_api::Result<TlsAcceptorBuilder> {
        #[cfg(any(target_os = "macos", target_os = "ios"))]
        {
            let (identity, certs) =
                pkcs12_to_sf_objects(pkcs12, passphrase).map_err(tls_api::Error::new)?;
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

    fn accept<'a, S>(&'a self, stream: S) -> BoxFuture<'a, tls_api::Result<tls_api::TlsStream<S>>>
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
            BoxFuture::new(async { crate::not_ios_or_macos() })
        }
    }
}
