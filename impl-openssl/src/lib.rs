extern crate tls_api;
extern crate openssl;

use std::io;
use std::result;
use std::fmt;

use tls_api::Error;
use tls_api::Result;
#[cfg(has_alpn)]
use openssl::ssl::AlpnError;


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
            return Err(Error::new_other("prototol len"));
        }
        r.push(proto.len() as u8);
        r.extend_from_slice(proto);
    }
    Ok(r)
}

#[cfg(test)]
#[test]
fn test_encode_alpn_protos() {
    assert_eq!(&b"\x06spdy/1\x08http/1.1"[..], &encode_alpn_protos(&[b"spdy/1", b"http/1.1"]).unwrap()[..]);
}


impl tls_api::TlsConnectorBuilder for TlsConnectorBuilder {
    type Connector = TlsConnector;

    type Underlying = openssl::ssl::SslConnectorBuilder;

    fn underlying_mut(&mut self) -> &mut openssl::ssl::SslConnectorBuilder {
        &mut self.builder
    }

    fn supports_alpn() -> bool {
        HAS_ALPN
    }

    #[cfg(has_alpn)]
    fn set_alpn_protocols(&mut self, protocols: &[&[u8]]) -> Result<()> {
        self.builder.set_alpn_protos(&encode_alpn_protos(protocols)?).map_err(Error::new)
    }

    #[cfg(not(has_alpn))]
    fn set_alpn_protocols(&mut self, _protocols: &[&[u8]]) -> Result<()> {
        Err(Error::new_other("openssl is compiled without alpn"))
    }

    fn set_verify_hostname(&mut self, verify: bool) -> Result<()> {
        self.verify_hostname = verify;
        Ok(())
    }

    fn add_root_certificate(&mut self, cert: tls_api::Certificate) -> Result<&mut Self> {
        let cert = match cert.format {
            tls_api::CertificateFormat::DER => openssl::x509::X509::from_der(&cert.bytes)
                .map_err(Error::new)?,
            tls_api::CertificateFormat::PEM => openssl::x509::X509::from_pem(&cert.bytes)
                .map_err(Error::new)?,
        };

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

#[derive(Debug)]
struct TlsStream<S : io::Read + io::Write + fmt::Debug>(openssl::ssl::SslStream<S>);

impl<S : io::Read + io::Write + fmt::Debug> TlsStream<S> {

}

impl<S : io::Read + io::Write + fmt::Debug> io::Read for TlsStream<S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf)
    }
}

impl<S : io::Read + io::Write + fmt::Debug> io::Write for TlsStream<S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}

impl<S : io::Read + io::Write + fmt::Debug + Send + Sync + 'static> tls_api::TlsStreamImpl<S> for TlsStream<S> {
    fn shutdown(&mut self) -> io::Result<()> {
        match self.0.shutdown() {
            Ok(_) => Ok(()),
            Err(ref e) if e.code() == openssl::ssl::ErrorCode::ZERO_RETURN => Ok(()),
            Err(e) => Err(io::Error::new(io::ErrorKind::Other, e)),
        }
    }

    fn get_mut(&mut self) -> &mut S {
        self.0.get_mut()
    }

    fn get_ref(&self) -> &S {
        self.0.get_ref()
    }

    #[cfg(has_alpn)]
    fn get_alpn_protocol(&self) -> Option<Vec<u8>> {
        self.0.ssl().selected_alpn_protocol().map(Vec::from)
    }

    #[cfg(not(has_alpn))]
    fn get_alpn_protocol(&self) -> Option<Vec<u8>> {
        None
    }
}


struct MidHandshakeTlsStream<S : io::Read + io::Write + 'static>(Option<openssl::ssl::MidHandshakeSslStream<S>>);

impl<S : io::Read + io::Write> fmt::Debug for MidHandshakeTlsStream<S> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("MidHandshakeTlsStream").finish()
    }
}




impl<S : io::Read + io::Write + fmt::Debug + Send + Sync + 'static> tls_api::MidHandshakeTlsStreamImpl<S> for MidHandshakeTlsStream<S> {
    fn handshake(&mut self) -> result::Result<tls_api::TlsStream<S>, tls_api::HandshakeError<S>> {
        self.0.take().unwrap().handshake()
            .map(|s| tls_api::TlsStream::new(TlsStream(s)))
            .map_err(map_handshake_error)
    }
}

fn map_handshake_error<S>(e: openssl::ssl::HandshakeError<S>) -> tls_api::HandshakeError<S>
    where S : io::Read + io::Write + fmt::Debug + Send + Sync + 'static
{
    match e {
        openssl::ssl::HandshakeError::SetupFailure(e) => {
            tls_api::HandshakeError::Failure(Error::new(e))
        }
        openssl::ssl::HandshakeError::Failure(e) => {
            tls_api::HandshakeError::Failure(Error::new(e.into_error()))
        },
        openssl::ssl::HandshakeError::WouldBlock(s) => {
            tls_api::HandshakeError::Interrupted(
                tls_api::MidHandshakeTlsStream::new(MidHandshakeTlsStream(Some(s))))
        }
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

    fn connect<S>(&self, domain: &str, stream: S)
        -> result::Result<tls_api::TlsStream<S>, tls_api::HandshakeError<S>>
            where S : io::Read + io::Write + fmt::Debug + Send + Sync + 'static
    {
        self.connector
            .configure().map_err(|e| tls_api::HandshakeError::Failure(Error::new(e)))?
            .verify_hostname(self.verify_hostname)
            .use_server_name_indication(false)
            .connect(domain, stream)
            .map(|s| tls_api::TlsStream::new(TlsStream(s)))
            .map_err(map_handshake_error)
    }
}


// TlsAcceptor and TlsAcceptorBuilder

impl TlsAcceptorBuilder {
    pub fn from_pkcs12(pkcs12: &[u8], password: &str) -> Result<TlsAcceptorBuilder> {
        let pkcs12 = openssl::pkcs12::Pkcs12::from_der(pkcs12).map_err(Error::new)?;
        let pkcs12 = pkcs12.parse(password).map_err(Error::new)?;

        let mut builder = openssl::ssl::SslAcceptor::mozilla_intermediate(
            openssl::ssl::SslMethod::tls()).map_err(Error::new)?;

        if let Some(chain) = pkcs12.chain {
            for x509 in chain {
                builder.add_extra_chain_cert(x509).map_err(Error::new)?;
            }
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

    fn supports_alpn() -> bool {
        HAS_ALPN
    }

    #[cfg(has_alpn)]
    fn set_alpn_protocols(&mut self, protocols: &[&[u8]]) -> Result<()> {
        let protocols = encode_alpn_protos(protocols)?;
        self.0.set_alpn_select_callback(move |_ssl, client_protocols| {
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

    fn accept<S>(&self, stream: S)
            -> result::Result<tls_api::TlsStream<S>, tls_api::HandshakeError<S>>
        where S : io::Read + io::Write + fmt::Debug + Send + Sync + 'static
    {
        self.0.accept(stream)
            .map(|s| tls_api::TlsStream::new(TlsStream(s)))
            .map_err(map_handshake_error)
    }
}
