extern crate tls_api;
extern crate openssl;

use std::io;
use std::result;
use std::fmt;

pub struct Pkcs12(openssl::pkcs12::ParsedPkcs12);
pub struct Certificate(openssl::x509::X509);

pub struct TlsConnectorBuilder(openssl::ssl::SslConnectorBuilder);
pub struct TlsConnector(openssl::ssl::SslConnector);

pub struct TlsAcceptorBuilder(openssl::ssl::SslAcceptorBuilder);
pub struct TlsAcceptor(openssl::ssl::SslAcceptor);

use tls_api::Error;
use tls_api::Result;


fn map_error_stack(e: openssl::error::ErrorStack) -> Error {
    Error::new(e)
}


impl tls_api::Pkcs12 for Pkcs12 {
    fn from_der(der: &[u8], password: &str) -> Result<Self> {
        let pkcs12 = openssl::pkcs12::Pkcs12::from_der(der).map_err(map_error_stack)?;
        let parsed = pkcs12.parse(password).map_err(map_error_stack)?;
        Ok(Pkcs12(parsed))
    }
}

impl tls_api::Certificate for Certificate {
    fn from_der(der: &[u8]) -> Result<Self> where Self: Sized {
        openssl::x509::X509::from_der(der)
            .map(Certificate)
            .map_err(Error::new)
    }
}

impl tls_api::TlsConnectorBuilder for TlsConnectorBuilder {
    type Connector = TlsConnector;

    fn add_root_certificate(&mut self, cert: Certificate) -> Result<&mut Self> {
        self.0
            .builder_mut()
            .cert_store_mut()
            .add_cert(cert.0)
                .map_err(map_error_stack)?;
        Ok(self)
    }

    fn build(self) -> Result<TlsConnector> {
        Ok(TlsConnector(self.0.build()))
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
            Ok(_) |
            Err(openssl::ssl::Error::ZeroReturn) => Ok(()),
            Err(openssl::ssl::Error::Stream(e)) |
            Err(openssl::ssl::Error::WantRead(e)) |
            Err(openssl::ssl::Error::WantWrite(e)) => Err(e),
            Err(e) => return Err(io::Error::new(io::ErrorKind::Other, e)),
        }
    }

    fn get_mut(&mut self) -> &mut S {
        self.0.get_mut()
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
            tls_api::HandshakeError::Failure(Error::new(openssl::ssl::Error::Ssl(e)))
        }
        openssl::ssl::HandshakeError::Failure(e) => {
            tls_api::HandshakeError::Failure(Error::new(e.into_error()))
        },
        openssl::ssl::HandshakeError::Interrupted(s) => {
            tls_api::HandshakeError::Interrupted(
                tls_api::MidHandshakeTlsStream::new(MidHandshakeTlsStream(Some(s))))
        }
    }
}

impl tls_api::TlsConnector for TlsConnector {
    type Builder = TlsConnectorBuilder;
    type Certificate = Certificate;

    fn builder() -> Result<TlsConnectorBuilder> {
        openssl::ssl::SslConnectorBuilder::new(openssl::ssl::SslMethod::tls())
            .map(TlsConnectorBuilder)
            .map_err(Error::new)
    }

    fn connect<S>(&self, domain: &str, stream: S)
        -> result::Result<tls_api::TlsStream<S>, tls_api::HandshakeError<S>>
            where S : io::Read + io::Write + fmt::Debug + Send + Sync + 'static
    {
        self.0.connect(domain, stream)
            .map(|s| tls_api::TlsStream::new(TlsStream(s)))
            .map_err(map_handshake_error)
    }

    fn danger_connect_without_providing_domain_for_certificate_verification_and_server_name_indication<S>(
        &self,
        stream: S)
        -> result::Result<tls_api::TlsStream<S>, tls_api::HandshakeError<S>>
            where S : io::Read + io::Write + fmt::Debug + Send + Sync + 'static
    {
        self.0.danger_connect_without_providing_domain_for_certificate_verification_and_server_name_indication(stream)
            .map(|s| tls_api::TlsStream::new(TlsStream(s)))
            .map_err(map_handshake_error)
    }
}

impl tls_api::TlsAcceptorBuilder for TlsAcceptorBuilder {
    type Acceptor = TlsAcceptor;

    fn build(self) -> Result<TlsAcceptor> {
        Ok(TlsAcceptor(self.0.build()))
    }
}

impl tls_api::TlsAcceptor for TlsAcceptor {
    type Pkcs12 = Pkcs12;
    type Builder = TlsAcceptorBuilder;

    fn builder(pkcs12: Pkcs12) -> Result<TlsAcceptorBuilder> {
        openssl::ssl::SslAcceptorBuilder::mozilla_intermediate(
            openssl::ssl::SslMethod::tls(),
            &pkcs12.0.pkey,
            &pkcs12.0.cert,
            &pkcs12.0.chain)
                .map(TlsAcceptorBuilder)
                .map_err(map_error_stack)
    }

    fn accept<S>(&self, stream: S)
            -> result::Result<tls_api::TlsStream<S>, tls_api::HandshakeError<S>>
        where S : io::Read + io::Write + fmt::Debug + Send + Sync + 'static
    {
        self.0.accept(stream)
            .map(|s| tls_api::TlsStream::new(TlsStream(s)))
            .map_err(map_handshake_error)
    }
}
