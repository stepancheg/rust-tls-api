use crate::encode_alpn_protos;
use crate::handshake::HandshakeFuture;
use crate::HAS_ALPN;
use openssl::pkcs12::ParsedPkcs12;
use std::fmt;
use tls_api::async_as_sync::AsyncIoAsSyncIo;
use tls_api::runtime::AsyncRead;
use tls_api::runtime::AsyncWrite;
use tls_api::BoxFuture;
use tls_api::Pkcs12AndPassword;

pub struct TlsAcceptorBuilder(pub openssl::ssl::SslAcceptorBuilder);

pub struct TlsAcceptor(pub openssl::ssl::SslAcceptor);

fn to_openssl_pkcs12(pkcs12_and_password: &Pkcs12AndPassword) -> tls_api::Result<ParsedPkcs12> {
    let pkcs12 = openssl::pkcs12::Pkcs12::from_der(&pkcs12_and_password.pkcs12.0)
        .map_err(tls_api::Error::new)?;
    pkcs12
        .parse(&pkcs12_and_password.password)
        .map_err(tls_api::Error::new)
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
        Err(tls_api::Error::new_other(
            "openssl is compiled without alpn",
        ))
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

impl tls_api::TlsAcceptor for TlsAcceptor {
    type Builder = TlsAcceptorBuilder;

    const IMPLEMENTED: bool = true;
    const SUPPORTS_ALPN: bool = HAS_ALPN;
    const SUPPORTS_DER_KEYS: bool = false; // TODO: actually supports
    const SUPPORTS_PKCS12_KEYS: bool = true;

    fn builder_from_pkcs12(pkcs12: &Pkcs12AndPassword) -> tls_api::Result<TlsAcceptorBuilder> {
        let mut builder =
            openssl::ssl::SslAcceptor::mozilla_intermediate(openssl::ssl::SslMethod::tls())
                .map_err(tls_api::Error::new)?;

        let pkcs12 = to_openssl_pkcs12(pkcs12)?;
        if let Some(chain) = pkcs12.chain {
            for x509 in chain {
                builder
                    .add_extra_chain_cert(x509)
                    .map_err(tls_api::Error::new)?;
            }
        } else {
            // panic!("no chain");
        }

        builder
            .set_certificate(&pkcs12.cert)
            .map_err(tls_api::Error::new)?;
        builder
            .set_private_key(&pkcs12.pkey)
            .map_err(tls_api::Error::new)?;

        Ok(TlsAcceptorBuilder(builder))
    }

    fn accept<'a, S>(&'a self, stream: S) -> BoxFuture<'a, tls_api::Result<tls_api::TlsStream<S>>>
    where
        S: AsyncRead + AsyncWrite + fmt::Debug + Unpin + Send + 'static,
    {
        BoxFuture::new(HandshakeFuture::Initial(
            move |stream| self.0.accept(stream),
            AsyncIoAsSyncIo::new(stream),
        ))
    }
}
