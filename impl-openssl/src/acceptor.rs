use openssl::pkcs12::ParsedPkcs12;

use tls_api::spi::async_as_sync::AsyncIoAsSyncIo;
use tls_api::spi_acceptor_common;
use tls_api::AsyncSocket;
use tls_api::AsyncSocketBox;
use tls_api::ImplInfo;

use crate::encode_alpn_protos;
use crate::handshake::HandshakeFuture;
use crate::HAS_ALPN;
use std::future::Future;

pub struct TlsAcceptorBuilder(pub openssl::ssl::SslAcceptorBuilder);

pub struct TlsAcceptor(pub openssl::ssl::SslAcceptor);

fn to_openssl_pkcs12(pkcs12: &[u8], passphrase: &str) -> tls_api::Result<ParsedPkcs12> {
    let pkcs12 = openssl::pkcs12::Pkcs12::from_der(pkcs12).map_err(tls_api::Error::new)?;
    pkcs12.parse(passphrase).map_err(tls_api::Error::new)
}

impl tls_api::TlsAcceptorBuilder for TlsAcceptorBuilder {
    type Acceptor = TlsAcceptor;

    type Underlying = openssl::ssl::SslAcceptorBuilder;

    fn underlying_mut(&mut self) -> &mut openssl::ssl::SslAcceptorBuilder {
        &mut self.0
    }

    #[cfg(has_alpn)]
    fn set_alpn_protocols(&mut self, protocols: &[&[u8]]) -> tls_api::Result<()> {
        let protocols = encode_alpn_protos(protocols)?;
        self.0
            .set_alpn_select_callback(move |_ssl, client_protocols| {
                match openssl::ssl::select_next_proto(&protocols, client_protocols) {
                    Some(selected) => Ok(selected),
                    None => Err(openssl::ssl::AlpnError::NOACK),
                }
            });
        Ok(())
    }

    #[cfg(not(has_alpn))]
    fn set_alpn_protocols(&mut self, _protocols: &[&[u8]]) -> tls_api::Result<()> {
        Err(tls_api::Error::new(crate::Error::CompiledWithoutAlpn))
    }

    fn build(self) -> tls_api::Result<TlsAcceptor> {
        Ok(TlsAcceptor(self.0.build()))
    }
}

impl TlsAcceptorBuilder {
    pub fn builder_mut(&mut self) -> &mut openssl::ssl::SslAcceptorBuilder {
        &mut self.0
    }
}

impl TlsAcceptor {
    fn accept_impl<'a, S>(
        &'a self,
        stream: S,
    ) -> impl Future<Output = tls_api::Result<crate::TlsStream<S>>> + 'a
    where
        S: AsyncSocket,
    {
        HandshakeFuture::Initial(
            move |stream| self.0.accept(stream),
            AsyncIoAsSyncIo::new(stream),
        )
    }
}

impl tls_api::TlsAcceptor for TlsAcceptor {
    type Builder = TlsAcceptorBuilder;

    type Underlying = openssl::ssl::SslAcceptor;
    type TlsStream = crate::TlsStream<AsyncSocketBox>;

    fn underlying_mut(&mut self) -> &mut Self::Underlying {
        &mut self.0
    }

    const IMPLEMENTED: bool = true;
    const SUPPORTS_ALPN: bool = HAS_ALPN;
    const SUPPORTS_DER_KEYS: bool = true;
    const SUPPORTS_PKCS12_KEYS: bool = true;

    fn info() -> ImplInfo {
        crate::into()
    }

    fn builder_from_der_key(cert: &[u8], key: &[u8]) -> tls_api::Result<TlsAcceptorBuilder> {
        let cert = openssl::x509::X509::from_der(cert).map_err(tls_api::Error::new)?;
        let pkey = openssl::pkey::PKey::private_key_from_der(key).map_err(tls_api::Error::new)?;

        let mut builder =
            openssl::ssl::SslAcceptor::mozilla_intermediate(openssl::ssl::SslMethod::tls())
                .map_err(tls_api::Error::new)?;

        builder
            .set_certificate(cert.as_ref())
            .map_err(tls_api::Error::new)?;
        builder
            .set_private_key(pkey.as_ref())
            .map_err(tls_api::Error::new)?;

        Ok(TlsAcceptorBuilder(builder))
    }

    fn builder_from_pkcs12(pkcs12: &[u8], passphrase: &str) -> tls_api::Result<TlsAcceptorBuilder> {
        let mut builder =
            openssl::ssl::SslAcceptor::mozilla_intermediate(openssl::ssl::SslMethod::tls())
                .map_err(tls_api::Error::new)?;

        let pkcs12 = to_openssl_pkcs12(pkcs12, passphrase)?;
        if let Some(chain) = pkcs12.chain {
            for x509 in chain {
                builder
                    .add_extra_chain_cert(x509)
                    .map_err(tls_api::Error::new)?;
            }
        }

        builder
            .set_certificate(&pkcs12.cert)
            .map_err(tls_api::Error::new)?;
        builder
            .set_private_key(&pkcs12.pkey)
            .map_err(tls_api::Error::new)?;

        Ok(TlsAcceptorBuilder(builder))
    }

    spi_acceptor_common!();
}
