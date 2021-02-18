use std::fmt;

use crate::handshake::HandshakeFuture;
use openssl::pkcs12::ParsedPkcs12;
#[cfg(has_alpn)]
use openssl::ssl::AlpnError;
use std::future::Future;
use std::pin::Pin;
use tls_api::async_as_sync::AsyncIoAsSyncIo;
use tls_api::runtime::AsyncRead;
use tls_api::runtime::AsyncWrite;
use tls_api::Error;
use tls_api::Pkcs12AndPassword;
use tls_api::Result;

mod handshake;
mod stream;

pub(crate) use stream::TlsStream;

pub struct TlsConnectorBuilder {
    pub builder: openssl::ssl::SslConnectorBuilder,
    pub verify_hostname: bool,
}

pub struct TlsConnector {
    pub connector: openssl::ssl::SslConnector,
    pub verify_hostname: bool,
}

pub struct TlsAcceptorBuilder(pub openssl::ssl::SslAcceptorBuilder);

pub struct TlsAcceptor(pub openssl::ssl::SslAcceptor);

// TODO: https://github.com/sfackler/rust-openssl/pull/646
#[cfg(has_alpn)]
pub const HAS_ALPN: bool = true;
#[cfg(not(has_alpn))]
pub const HAS_ALPN: bool = false;

fn encode_alpn_protos(protos: &[&[u8]]) -> Result<Vec<u8>> {
    let mut r = Vec::new();
    for proto in protos {
        if proto.len() > 255 {
            return Err(Error::new_other("protocol len"));
        }
        r.push(proto.len() as u8);
        r.extend_from_slice(proto);
    }
    Ok(r)
}

#[cfg(test)]
#[test]
fn test_encode_alpn_protos() {
    assert_eq!(
        &b"\x06spdy/1\x08http/1.1"[..],
        &encode_alpn_protos(&[b"spdy/1", b"http/1.1"]).unwrap()[..]
    );
}

impl tls_api::TlsConnectorBuilder for TlsConnectorBuilder {
    type Connector = TlsConnector;

    type Underlying = openssl::ssl::SslConnectorBuilder;

    fn underlying_mut(&mut self) -> &mut openssl::ssl::SslConnectorBuilder {
        &mut self.builder
    }

    const SUPPORTS_ALPN: bool = HAS_ALPN;

    #[cfg(has_alpn)]
    fn set_alpn_protocols(&mut self, protocols: &[&[u8]]) -> Result<()> {
        self.builder
            .set_alpn_protos(&encode_alpn_protos(protocols)?)
            .map_err(Error::new)
    }

    #[cfg(not(has_alpn))]
    fn set_alpn_protocols(&mut self, _protocols: &[&[u8]]) -> Result<()> {
        Err(Error::new_other("openssl is compiled without alpn"))
    }

    fn set_verify_hostname(&mut self, verify: bool) -> Result<()> {
        self.verify_hostname = verify;
        Ok(())
    }

    fn add_root_certificate(&mut self, cert: &tls_api::X509Cert) -> Result<&mut Self> {
        let cert = openssl::x509::X509::from_der(cert.as_bytes()).map_err(Error::new)?;

        self.builder
            .cert_store_mut()
            .add_cert(cert)
            .map_err(Error::new)?;

        Ok(self)
    }

    fn build(self) -> Result<TlsConnector> {
        Ok(TlsConnector {
            connector: self.builder.build(),
            verify_hostname: self.verify_hostname,
        })
    }
}

impl TlsConnectorBuilder {
    pub fn builder_mut(&mut self) -> &mut openssl::ssl::SslConnectorBuilder {
        &mut self.builder
    }
}

impl tls_api::TlsConnector for TlsConnector {
    type Builder = TlsConnectorBuilder;

    fn builder() -> Result<TlsConnectorBuilder> {
        let builder = openssl::ssl::SslConnector::builder(openssl::ssl::SslMethod::tls())
            .map_err(Error::new)?;
        Ok(TlsConnectorBuilder {
            builder,
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
        let client_configuration = match self.connector.configure() {
            Ok(client_configuration) => client_configuration,
            Err(e) => return Box::pin(async { Err(tls_api::Error::new(e)) }),
        };
        let client_configuration = client_configuration.verify_hostname(self.verify_hostname);
        Box::pin(HandshakeFuture::Initial(
            move |stream| client_configuration.connect(domain, stream),
            AsyncIoAsSyncIo::new(stream),
        ))
    }
}

// TlsAcceptor and TlsAcceptorBuilder

fn to_openssl_pkcs12(pkcs12_and_password: &Pkcs12AndPassword) -> Result<ParsedPkcs12> {
    let pkcs12 =
        openssl::pkcs12::Pkcs12::from_der(&pkcs12_and_password.pkcs12.0).map_err(Error::new)?;
    pkcs12
        .parse(&pkcs12_and_password.password)
        .map_err(Error::new)
}

impl TlsAcceptorBuilder {
    pub fn from_pkcs12(server_pkcs12: &Pkcs12AndPassword) -> Result<TlsAcceptorBuilder> {
        let mut builder =
            openssl::ssl::SslAcceptor::mozilla_intermediate(openssl::ssl::SslMethod::tls())
                .map_err(Error::new)?;

        let pkcs12 = to_openssl_pkcs12(server_pkcs12)?;
        if let Some(chain) = pkcs12.chain {
            for x509 in chain {
                builder.add_extra_chain_cert(x509).map_err(Error::new)?;
            }
        } else {
            // panic!("no chain");
        }

        builder.set_certificate(&pkcs12.cert).map_err(Error::new)?;
        builder.set_private_key(&pkcs12.pkey).map_err(Error::new)?;

        Ok(TlsAcceptorBuilder(builder))
    }
}

impl tls_api::TlsAcceptorBuilder for TlsAcceptorBuilder {
    type Acceptor = TlsAcceptor;

    type Underlying = openssl::ssl::SslAcceptorBuilder;

    fn underlying_mut(&mut self) -> &mut openssl::ssl::SslAcceptorBuilder {
        &mut self.0
    }

    const SUPPORTS_ALPN: bool = HAS_ALPN;

    #[cfg(has_alpn)]
    fn set_alpn_protocols(&mut self, protocols: &[&[u8]]) -> Result<()> {
        let protocols = encode_alpn_protos(protocols)?;
        self.0
            .set_alpn_select_callback(move |_ssl, client_protocols| {
                match openssl::ssl::select_next_proto(&protocols, client_protocols) {
                    Some(selected) => Ok(selected),
                    None => Err(AlpnError::NOACK),
                }
            });
        Ok(())
    }

    #[cfg(not(has_alpn))]
    fn set_alpn_protocols(&mut self, _protocols: &[&[u8]]) -> Result<()> {
        Err(Error::new_other("openssl is compiled without alpn"))
    }

    fn build(self) -> Result<TlsAcceptor> {
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

    fn accept<'a, S>(
        &'a self,
        stream: S,
    ) -> Pin<Box<dyn Future<Output = tls_api::Result<tls_api::TlsStream<S>>> + Send + 'a>>
    where
        S: AsyncRead + AsyncWrite + fmt::Debug + Unpin + Send + Sync + 'static,
    {
        Box::pin(HandshakeFuture::Initial(
            move |stream| self.0.accept(stream),
            AsyncIoAsSyncIo::new(stream),
        ))
    }
}
