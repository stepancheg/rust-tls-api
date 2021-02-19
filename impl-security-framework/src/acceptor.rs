use crate::handshake::ServerHandshakeFuture;

#[cfg(any(target_os = "macos", target_os = "ios"))]
use security_framework::certificate::SecCertificate;
#[cfg(any(target_os = "macos", target_os = "ios"))]
use security_framework::identity::SecIdentity;
#[cfg(any(target_os = "macos", target_os = "ios"))]
use security_framework::import_export::Pkcs12ImportOptions;
#[cfg(any(target_os = "macos", target_os = "ios"))]
use security_framework::secure_transport::SslConnectionType;
#[cfg(any(target_os = "macos", target_os = "ios"))]
use security_framework::secure_transport::SslContext;
#[cfg(any(target_os = "macos", target_os = "ios"))]
use security_framework::secure_transport::SslProtocolSide;

use std::fmt;

use crate::not_is_or_macos;
use tls_api::async_as_sync::AsyncIoAsSyncIo;
use tls_api::runtime::AsyncRead;
use tls_api::runtime::AsyncWrite;
use tls_api::BoxFuture;
use tls_api::Pkcs12AndPassword;

pub struct SecureTransportTlsAcceptorBuilder {
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    pub identity: SecIdentity,
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    pub certs: Vec<SecCertificate>,
}

pub struct TlsAcceptor(SecureTransportTlsAcceptorBuilder);
pub struct TlsAcceptorBuilder(SecureTransportTlsAcceptorBuilder);

impl tls_api::TlsAcceptorBuilder for TlsAcceptorBuilder {
    type Acceptor = TlsAcceptor;
    type Underlying = SecureTransportTlsAcceptorBuilder;

    fn set_alpn_protocols(&mut self, _protocols: &[&[u8]]) -> tls_api::Result<()> {
        return Err(tls_api::Error::new_other(
            "security-framework does not support ALPN on acceptor side",
        ));
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
    pkcs12: &Pkcs12AndPassword,
) -> tls_api::Result<(SecIdentity, Vec<SecCertificate>)> {
    let imported_identities = Pkcs12ImportOptions::new()
        .passphrase(&pkcs12.password)
        .import(&pkcs12.pkcs12.0)
        .map_err(tls_api::Error::new)?;
    let mut identities: Vec<(SecIdentity, Vec<SecCertificate>)> = imported_identities
        .into_iter()
        .flat_map(|i| {
            let cert_chain = i.cert_chain;
            i.identity.map(|i| (i, cert_chain.unwrap_or(Vec::new())))
        })
        .collect();
    if identities.len() == 0 {
        return Err(tls_api::Error::new_other("identities not found in pkcs12"));
    } else if identities.len() == 1 {
        Ok(identities.pop().unwrap())
    } else {
        return Err(tls_api::Error::new_other(&format!(
            "too many identities found in pkcs12: {}",
            identities.len()
        )));
    }
}

impl tls_api::TlsAcceptor for TlsAcceptor {
    type Builder = TlsAcceptorBuilder;

    const SUPPORTS_ALPN: bool = false;
    const SUPPORTS_DER_KEYS: bool = false;
    const SUPPORTS_PKCS12_KEYS: bool = true;

    fn builder_from_pkcs12(pkcs12: &Pkcs12AndPassword) -> tls_api::Result<TlsAcceptorBuilder> {
        #[cfg(any(target_os = "macos", target_os = "ios"))]
        {
            let (identity, certs) = pkcs12_to_sf_objects(pkcs12).map_err(tls_api::Error::new)?;
            Ok(TlsAcceptorBuilder(SecureTransportTlsAcceptorBuilder {
                identity,
                certs,
            }))
        }
        #[cfg(not(any(target_os = "macos", target_os = "ios")))]
        {
            not_is_or_macos()
        }
    }

    fn accept<'a, S>(&'a self, stream: S) -> BoxFuture<'a, tls_api::Result<tls_api::TlsStream<S>>>
    where
        S: AsyncRead + AsyncWrite + fmt::Debug + Unpin + Send + 'static,
    {
        #[cfg(any(target_os = "macos", target_os = "ios"))]
        {
            BoxFuture::new(async move {
                let mut ctx = SslContext::new(SslProtocolSide::SERVER, SslConnectionType::STREAM)
                    .map_err(tls_api::Error::new)?;
                ctx.set_certificate(&self.0.identity, &self.0.certs)
                    .map_err(tls_api::Error::new)?;
                ServerHandshakeFuture::Initial(
                    move |s| ctx.handshake(s),
                    AsyncIoAsSyncIo::new(stream),
                )
                .await
            })
        }
        #[cfg(not(any(target_os = "macos", target_os = "ios")))]
        {
            not_is_or_macos()
        }
    }
}
