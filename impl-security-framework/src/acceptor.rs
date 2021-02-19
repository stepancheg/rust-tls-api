use crate::handshake::ServerHandshakeFuture;

use security_framework::certificate::SecCertificate;
use security_framework::identity::SecIdentity;
use security_framework::import_export::Pkcs12ImportOptions;
use security_framework::secure_transport::SslConnectionType;
use security_framework::secure_transport::SslContext;
use security_framework::secure_transport::SslProtocolSide;

use std::fmt;

use tls_api::async_as_sync::AsyncIoAsSyncIo;
use tls_api::runtime::AsyncRead;
use tls_api::runtime::AsyncWrite;
use tls_api::BoxFuture;
use tls_api::Pkcs12AndPassword;

pub struct SecureTransportTlsAcceptorBuilder {
    pub identity: SecIdentity,
    pub certs: Vec<SecCertificate>,
}

pub struct TlsAcceptor(SecureTransportTlsAcceptorBuilder);
pub struct TlsAcceptorBuilder(SecureTransportTlsAcceptorBuilder);

impl tls_api::TlsAcceptorBuilder for TlsAcceptorBuilder {
    type Acceptor = TlsAcceptor;
    type Underlying = SecureTransportTlsAcceptorBuilder;

    fn set_alpn_protocols(&mut self, _protocols: &[&[u8]]) -> tls_api::Result<()> {
        // TODO
        unimplemented!()
    }

    fn underlying_mut(&mut self) -> &mut Self::Underlying {
        &mut self.0
    }

    fn build(self) -> tls_api::Result<Self::Acceptor> {
        Ok(TlsAcceptor(self.0))
    }
}

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
        let (identity, certs) = pkcs12_to_sf_objects(pkcs12).map_err(tls_api::Error::new)?;
        Ok(TlsAcceptorBuilder(SecureTransportTlsAcceptorBuilder {
            identity,
            certs,
        }))
    }

    fn accept<'a, S>(&'a self, stream: S) -> BoxFuture<'a, tls_api::Result<tls_api::TlsStream<S>>>
    where
        S: AsyncRead + AsyncWrite + fmt::Debug + Unpin + Send + 'static,
    {
        BoxFuture::new(async move {
            let mut ctx = SslContext::new(SslProtocolSide::SERVER, SslConnectionType::STREAM)
                .map_err(tls_api::Error::new)?;
            ctx.set_certificate(&self.0.identity, &self.0.certs)
                .map_err(tls_api::Error::new)?;
            ServerHandshakeFuture::Initial(move |s| ctx.handshake(s), AsyncIoAsSyncIo::new(stream))
                .await
        })
    }
}
