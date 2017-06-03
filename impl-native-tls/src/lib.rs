extern crate tls_api;
extern crate native_tls;

use std::io;
use std::result;
use std::fmt;

pub struct Pkcs12(native_tls::Pkcs12);
pub struct Certificate(native_tls::Certificate);

pub struct TlsConnectorBuilder(native_tls::TlsConnectorBuilder);
pub struct TlsConnector(native_tls::TlsConnector);

pub struct TlsAcceptorBuilder(native_tls::TlsAcceptorBuilder);
pub struct TlsAcceptor(native_tls::TlsAcceptor);

use tls_api::Error;
use tls_api::Result;

impl tls_api::Pkcs12 for Pkcs12 {
    fn from_der(der: &[u8], password: &str) -> Result<Self> {
        native_tls::Pkcs12::from_der(der, password)
            .map(Pkcs12)
            .map_err(Error::new)
    }
}

impl tls_api::Certificate for Certificate {
    fn from_der(der: &[u8]) -> Result<Self> where Self: Sized {
        native_tls::Certificate::from_der(der)
            .map(Certificate)
            .map_err(Error::new)
    }
}

impl tls_api::TlsConnectorBuilder for TlsConnectorBuilder {
    type Connector = TlsConnector;

    fn add_root_certificate(&mut self, cert: Certificate) -> Result<&mut Self> {
        self.0.add_root_certificate(cert.0).map_err(Error::new)?;
        Ok(self)
    }

    fn build(self) -> Result<TlsConnector> {
        self.0.build()
            .map(TlsConnector)
            .map_err(Error::new)
    }
}

#[derive(Debug)]
struct TlsStream<S : io::Read + io::Write + fmt::Debug>(native_tls::TlsStream<S>);

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
        self.0.shutdown()
    }

    fn get_mut(&mut self) -> &mut S {
        self.0.get_mut()
    }
}


struct MidHandshakeTlsStream<S : io::Read + io::Write + 'static>(Option<native_tls::MidHandshakeTlsStream<S>>);

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

fn map_handshake_error<S>(e: native_tls::HandshakeError<S>) -> tls_api::HandshakeError<S>
    where S : io::Read + io::Write + Send + Sync + fmt::Debug + 'static
{
    match e {
        native_tls::HandshakeError::Failure(e) => {
            tls_api::HandshakeError::Failure(Error::new(e))
        },
        native_tls::HandshakeError::Interrupted(s) => {
            tls_api::HandshakeError::Interrupted(
                tls_api::MidHandshakeTlsStream::new(MidHandshakeTlsStream(Some(s))))
        },
    }
}

impl tls_api::TlsConnector for TlsConnector {
    type Builder = TlsConnectorBuilder;
    type Certificate = Certificate;

    fn builder() -> Result<TlsConnectorBuilder> {
        native_tls::TlsConnector::builder()
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
        self.0.build()
            .map(TlsAcceptor)
            .map_err(Error::new)
    }
}

impl tls_api::TlsAcceptor for TlsAcceptor {
    type Pkcs12 = Pkcs12;
    type Builder = TlsAcceptorBuilder;

    fn builder(pkcs12: Pkcs12) -> Result<TlsAcceptorBuilder> {
        native_tls::TlsAcceptor::builder(pkcs12.0)
            .map(TlsAcceptorBuilder)
            .map_err(Error::new)
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
