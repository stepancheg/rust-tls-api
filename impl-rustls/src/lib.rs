extern crate tls_api;
extern crate rustls;
extern crate webpki_roots;

use std::io;
use std::result;
use std::fmt;
use std::sync::Arc;
use std::mem;

use tls_api::Result;
use tls_api::Error;

use rustls::Session as rustls_Session;


pub struct Pkcs12();
pub struct Certificate();

pub struct TlsConnectorBuilder(rustls::ClientConfig);
pub struct TlsConnector(Arc<rustls::ClientConfig>);

pub struct TlsAcceptorBuilder(rustls::ServerConfig);
pub struct TlsAcceptor(rustls::ServerConfig);


impl tls_api::Pkcs12 for Pkcs12 {
    fn from_der(_der: &[u8], _password: &str) -> Result<Self> {
        unimplemented!()
    }
}

impl tls_api::Certificate for Certificate {
    fn from_der(_der: &[u8]) -> Result<Self> where Self: Sized {
        unimplemented!()
    }
}


pub struct TlsStream<S : io::Read + io::Write + fmt::Debug + Send + Sync + 'static> {
    stream: S,
    session: rustls::ClientSession,
    // Amount of data buffered in session
    write_skip: usize,
}

enum IntermediateError {
    Io(io::Error),
    Tls(rustls::TLSError),
}

impl IntermediateError {
    fn into_error(self) -> Error {
        match self {
            IntermediateError::Io(err) => Error::new(err),
            IntermediateError::Tls(err) => Error::new(err),
        }
    }
}

impl From<io::Error> for IntermediateError {
    fn from(err: io::Error) -> IntermediateError {
        IntermediateError::Io(err)
    }
}

impl From<rustls::TLSError> for IntermediateError {
    fn from(err: rustls::TLSError) -> IntermediateError {
        IntermediateError::Tls(err)
    }
}

impl<S : io::Read + io::Write + fmt::Debug + Send + Sync + 'static> TlsStream<S> {

    fn complete_handshake(&mut self) -> result::Result<(), IntermediateError> {
        while self.session.is_handshaking() {
            // TODO: https://github.com/ctz/rustls/issues/77
            if self.session.is_handshaking() && self.session.wants_write() {
                while self.session.write_tls(&mut self.stream)? > 0 {
                };
            }
            if self.session.is_handshaking() && self.session.wants_read() {
                self.session.read_tls(&mut self.stream)?;
                self.session.process_new_packets()?;
            }
        }

        Ok(())
    }

    fn complete_handleshake_mid(mut self)
        -> result::Result<tls_api::TlsStream<S>, tls_api::HandshakeError<S>>
    {
        match self.complete_handshake() {
            Ok(_) => {
                Ok(tls_api::TlsStream::new(self))
            },
            Err(IntermediateError::Io(ref e)) if e.kind() == io::ErrorKind::WouldBlock => {
                let mid_handshake = tls_api::MidHandshakeTlsStream::new(MidHandshakeTlsStream {
                    stream: Some(self)
                });
                Err(tls_api::HandshakeError::Interrupted(mid_handshake))
            }
            Err(e) => {
                Err(tls_api::HandshakeError::Failure(e.into_error()))
            },
        }
    }
}

impl<S : io::Read + io::Write + fmt::Debug + Send + Sync + 'static> fmt::Debug for TlsStream<S> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("TlsStream")
            .field("stream", &self.stream)
            .field("session", &"...")
            .finish()
    }
}

impl<S : io::Read + io::Write + fmt::Debug + Send + Sync + 'static> io::Read for TlsStream<S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let r = self.session.read(buf)?;
        if r > 0 {
            return Ok(r);
        }

        self.session.read_tls(&mut self.stream)?;
        self.session.process_new_packets()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        self.session.read(buf)
    }
}

impl<S : io::Read + io::Write + fmt::Debug + Send + Sync + 'static> io::Write for TlsStream<S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // Flush previously written data
        self.session.write_tls(&mut self.stream)?;

        // Must write the same buffer after previous failure
        let r = self.session.write(&buf[self.write_skip..])?;
        self.write_skip += r;

        self.session.write_tls(&mut self.stream)?;

        Ok(mem::replace(&mut self.write_skip, 0))
    }

    fn flush(&mut self) -> io::Result<()> {
        self.session.flush()?;
        self.session.write_tls(&mut self.stream)?;
        Ok(())
    }
}

impl<S : io::Read + io::Write + fmt::Debug + Send + Sync + 'static> tls_api::TlsStreamImpl<S> for TlsStream<S> {
    fn shutdown(&mut self) -> io::Result<()> {
        // TODO: do something
        Ok(())
    }

    fn get_mut(&mut self) -> &mut S {
        &mut self.stream
    }
}

#[derive(Debug)]
pub struct MidHandshakeTlsStream<S : io::Read + io::Write + fmt::Debug + Send + Sync + 'static> {
    stream: Option<TlsStream<S>>
}

impl<S : io::Read + io::Write + fmt::Debug + Send + Sync + 'static>
    tls_api::MidHandshakeTlsStreamImpl<S> for MidHandshakeTlsStream<S>
{
    fn handshake(&mut self) -> result::Result<tls_api::TlsStream<S>, tls_api::HandshakeError<S>> {
        self.stream.take().unwrap().complete_handleshake_mid()
    }
}



impl tls_api::TlsConnectorBuilder for TlsConnectorBuilder {
    type Connector = TlsConnector;

    type Underlying = rustls::ClientConfig;

    fn underlying_mut(&mut self) -> &mut rustls::ClientConfig {
        &mut self.0
    }

    fn add_root_certificate(&mut self, _cert: Certificate) -> Result<&mut Self> {
        unimplemented!()
    }

    fn build(mut self) -> Result<TlsConnector> {
        self.0.root_store.add_trust_anchors(&webpki_roots::ROOTS);
        Ok(TlsConnector(Arc::new(self.0)))
    }
}

impl tls_api::TlsConnector for TlsConnector {
    type Builder = TlsConnectorBuilder;
    type Certificate = Certificate;

    fn builder() -> Result<TlsConnectorBuilder> {
        Ok(TlsConnectorBuilder(rustls::ClientConfig::new()))
    }

    fn connect<S>(&self, domain: &str, stream: S)
        -> result::Result<tls_api::TlsStream<S>, tls_api::HandshakeError<S>>
            where S : io::Read + io::Write + fmt::Debug + Send + Sync + 'static
    {
        let tls_stream = TlsStream {
            stream: stream,
            session: rustls::ClientSession::new(&self.0, domain),
            write_skip: 0,
        };

        tls_stream.complete_handleshake_mid()
    }

    fn danger_connect_without_providing_domain_for_certificate_verification_and_server_name_indication<S>(
        &self,
        stream: S)
        -> result::Result<tls_api::TlsStream<S>, tls_api::HandshakeError<S>>
            where S : io::Read + io::Write + fmt::Debug + Send + Sync + 'static
    {
        // TODO: Clone current config: https://github.com/ctz/rustls/pull/78
        let mut client_config = rustls::ClientConfig::new();

        struct NoCertificateVerifier;

        impl rustls::ServerCertVerifier for NoCertificateVerifier {
            fn verify_server_cert(
                &self,
                _roots: &rustls::RootCertStore,
                _presented_certs: &[rustls::Certificate],
                _dns_name: &str)
                    -> result::Result<(), rustls::TLSError>
            {
                Ok(())
            }
        }

        client_config.dangerous().set_certificate_verifier(Box::new(NoCertificateVerifier));

        let tls_stream = TlsStream {
            stream: stream,
            session: rustls::ClientSession::new(&Arc::new(client_config), "ignore"),
            write_skip: 0,
        };

        tls_stream.complete_handleshake_mid()
    }
}

impl tls_api::TlsAcceptorBuilder for TlsAcceptorBuilder {
    type Acceptor = TlsAcceptor;

    type Underlying = rustls::ServerConfig;

    fn underlying_mut(&mut self) -> &mut rustls::ServerConfig {
        &mut self.0
    }

    fn build(self) -> Result<TlsAcceptor> {
        Ok(TlsAcceptor(self.0))
    }
}

impl tls_api::TlsAcceptor for TlsAcceptor {
    type Pkcs12 = Pkcs12;
    type Builder = TlsAcceptorBuilder;

    fn builder(_pkcs12: Pkcs12) -> Result<TlsAcceptorBuilder> {
        Ok(TlsAcceptorBuilder(rustls::ServerConfig::new()))
    }

    fn accept<S>(&self, _stream: S)
            -> result::Result<tls_api::TlsStream<S>, tls_api::HandshakeError<S>>
        where S : io::Read + io::Write + fmt::Debug + Send + Sync + 'static
    {
        unimplemented!()
    }
}
