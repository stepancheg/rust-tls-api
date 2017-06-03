extern crate tls_api;
extern crate native_tls;

use std::io;
use std::result;

pub struct Pkcs12(native_tls::Pkcs12);
pub struct Certificate(native_tls::Certificate);

pub struct TlsConnectorBuilder(native_tls::TlsConnectorBuilder);
pub struct TlsConnector(native_tls::TlsConnector);

pub struct TlsAcceptorBuilder(native_tls::TlsAcceptorBuilder);
pub struct TlsAcceptor(native_tls::TlsAcceptor);

use tls_api::Error;
use tls_api::Result;

impl tls_api::Pkcs12 for Pkcs12 {
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

trait TlsStreamTrait : io::Read + io::Write {
}

impl <S : io::Read + io::Write> TlsStreamTrait for native_tls::TlsStream<S> {
}

pub struct TlsStream(Box<TlsStreamTrait>);

impl io::Read for TlsStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf)
    }
}

impl io::Write for TlsStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}

impl tls_api::TlsStream for TlsStream {
    
}

trait MidHandshakeTlsStreamTrait {
    fn handshake(&mut self) -> result::Result<TlsStream, tls_api::HandshakeError<MidHandshakeTlsStream>>;
}

impl<S : io::Read + io::Write + 'static> MidHandshakeTlsStreamTrait for Option<native_tls::MidHandshakeTlsStream<S>> {
    fn handshake(&mut self) -> result::Result<TlsStream, tls_api::HandshakeError<MidHandshakeTlsStream>> {
        self.take().unwrap().handshake()
            .map(|s| TlsStream(Box::new(s)))
            .map_err(|e| match e {
                native_tls::HandshakeError::Failure(e) => {
                    tls_api::HandshakeError::Failure(Error::new(e))
                },
                native_tls::HandshakeError::Interrupted(s) => {
                    // TODO: reuse previously allocated memory
                    tls_api::HandshakeError::Interrupted(MidHandshakeTlsStream(Box::new(Some(s))))
                },
            })
    }
}

pub struct MidHandshakeTlsStream(Box<MidHandshakeTlsStreamTrait>);

impl tls_api::MidHandshakeTlsStream for MidHandshakeTlsStream {
    type TlsStream = TlsStream;

    fn handshake(mut self) -> result::Result<TlsStream, tls_api::HandshakeError<MidHandshakeTlsStream>> {
        self.0.handshake()
    }
}

impl tls_api::TlsConnector for TlsConnector {
    type Builder = TlsConnectorBuilder;
    type Certificate = Certificate;
    type Pkcs12 = Pkcs12;

    fn builder() -> Result<TlsConnectorBuilder> {
        native_tls::TlsConnector::builder()
            .map(TlsConnectorBuilder)
            .map_err(Error::new)
    }
    type TlsStream = TlsStream;
    type MidHandshakeTlsStream = MidHandshakeTlsStream;

    fn connect<S>(&self, domain: &str, stream: S)
        -> result::Result<TlsStream, tls_api::HandshakeError<MidHandshakeTlsStream>>
            where S: io::Read + io::Write + 'static
    {
        self.0.connect(domain, stream)
            .map(|s| TlsStream(Box::new(s)))
            .map_err(|e| match e {
                native_tls::HandshakeError::Failure(e) => {
                    tls_api::HandshakeError::Failure(Error::new(e))
                },
                native_tls::HandshakeError::Interrupted(s) => {
                    tls_api::HandshakeError::Interrupted(MidHandshakeTlsStream(Box::new(Some(s))))
                },
            })
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
    type TlsStream = TlsStream;
    type MidHandshakeTlsStream = MidHandshakeTlsStream;

    fn builder(pkcs12: Pkcs12) -> Result<TlsAcceptorBuilder> {
        native_tls::TlsAcceptor::builder(pkcs12.0)
            .map(TlsAcceptorBuilder)
            .map_err(Error::new)
    }

    fn accept<S>(&self, stream: S)
            -> result::Result<TlsStream, tls_api::HandshakeError<MidHandshakeTlsStream>>
        where S: io::Read + io::Write + 'static
    {
        self.0.accept(stream)
            .map(|s| TlsStream(Box::new(s)))
            .map_err(|e| match e {
                native_tls::HandshakeError::Failure(e) => {
                    tls_api::HandshakeError::Failure(Error::new(e))
                },
                native_tls::HandshakeError::Interrupted(s) => {
                    tls_api::HandshakeError::Interrupted(MidHandshakeTlsStream(Box::new(Some(s))))
                },
            })         
    }
}
