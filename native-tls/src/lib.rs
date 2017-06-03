extern crate tls_api;
extern crate native_tls;

use std::io;

pub struct Pkcs12(native_tls::Pkcs12);
pub struct Certificate(native_tls::Certificate);

pub struct TlsConnectorBuilder(native_tls::TlsConnectorBuilder);
pub struct TlsConnector(native_tls::TlsConnector);

pub struct TlsAcceptorBuilder(native_tls::TlsAcceptorBuilder);
pub struct TlsAcceptor(native_tls::TlsAcceptor);

impl tls_api::Pkcs12 for Pkcs12 {
}

impl tls_api::Certificate for Certificate {
    type Error = native_tls::Error;

    fn from_der(der: &[u8]) -> Result<Self, native_tls::Error> where Self: Sized {
        native_tls::Certificate::from_der(der).map(Certificate)
    }
}

impl tls_api::TlsConnectorBuilder for TlsConnectorBuilder {
    type Connector = TlsConnector;

    fn add_root_certificate(&mut self, cert: Certificate) -> Result<&mut Self, native_tls::Error> {
        self.0.add_root_certificate(cert.0)?;
        Ok(self)
    }

    fn build(self) -> Result<TlsConnector, native_tls::Error> {
        self.0.build().map(TlsConnector)
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
    fn handshake(&mut self) -> Result<TlsStream, tls_api::HandshakeError<native_tls::Error, MidHandshakeTlsStream>>;
}

impl<S : io::Read + io::Write + 'static> MidHandshakeTlsStreamTrait for Option<native_tls::MidHandshakeTlsStream<S>> {
    fn handshake(&mut self) -> Result<TlsStream, tls_api::HandshakeError<native_tls::Error, MidHandshakeTlsStream>> {
        self.take().unwrap().handshake()
            .map(|s| TlsStream(Box::new(s)))
            .map_err(|e| match e {
                native_tls::HandshakeError::Failure(e) => {
                    tls_api::HandshakeError::Failure(e)
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
    type Error = native_tls::Error;
    type TlsStream = TlsStream;

    fn handshake(mut self) -> Result<TlsStream, tls_api::HandshakeError<native_tls::Error, MidHandshakeTlsStream>> {
        self.0.handshake()
    }
}

impl tls_api::TlsConnector for TlsConnector {
    type Builder = TlsConnectorBuilder;
    type Error = native_tls::Error;
    type Certificate = Certificate;
    type Pkcs12 = Pkcs12;

    fn builder() -> Result<TlsConnectorBuilder, native_tls::Error> {
        native_tls::TlsConnector::builder().map(TlsConnectorBuilder)
    }
    type TlsStream = TlsStream;
    type MidHandshakeTlsStream = MidHandshakeTlsStream;

    fn connect<S>(&self, domain: &str, stream: S)
        -> Result<TlsStream, tls_api::HandshakeError<native_tls::Error, MidHandshakeTlsStream>>
            where S: io::Read + io::Write + 'static
    {
        self.0.connect(domain, stream)
            .map(|s| TlsStream(Box::new(s)))
            .map_err(|e| match e {
                native_tls::HandshakeError::Failure(e) => {
                    tls_api::HandshakeError::Failure(e)
                },
                native_tls::HandshakeError::Interrupted(s) => {
                    tls_api::HandshakeError::Interrupted(MidHandshakeTlsStream(Box::new(Some(s))))
                },
            })
    }
}

impl tls_api::TlsAcceptorBuilder for TlsAcceptorBuilder {
    type Acceptor = TlsAcceptor;

    fn build(self) -> Result<TlsAcceptor, native_tls::Error> {
        self.0.build()
            .map(TlsAcceptor)
    }
}

impl tls_api::TlsAcceptor for TlsAcceptor {
    type Error = native_tls::Error;
    type Pkcs12 = Pkcs12;
    type Builder = TlsAcceptorBuilder;
    type TlsStream = TlsStream;
    type MidHandshakeTlsStream = MidHandshakeTlsStream;

    fn builder(pkcs12: Pkcs12) -> Result<TlsAcceptorBuilder, native_tls::Error> {
        native_tls::TlsAcceptor::builder(pkcs12.0)
            .map(TlsAcceptorBuilder)
    }

    fn accept<S>(&self, stream: S)
            -> Result<TlsStream, tls_api::HandshakeError<native_tls::Error, MidHandshakeTlsStream>>
        where S: io::Read + io::Write + 'static
    {
        self.0.accept(stream)
            .map(|s| TlsStream(Box::new(s)))
            .map_err(|e| match e {
                native_tls::HandshakeError::Failure(e) => {
                    tls_api::HandshakeError::Failure(e)
                },
                native_tls::HandshakeError::Interrupted(s) => {
                    tls_api::HandshakeError::Interrupted(MidHandshakeTlsStream(Box::new(Some(s))))
                },
            })         
    }
}
