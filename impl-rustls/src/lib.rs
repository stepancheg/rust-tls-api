extern crate tls_api;
extern crate rustls;
extern crate webpki_roots;
extern crate webpki;

use std::io;
use std::result;
use std::fmt;
use std::sync::Arc;
use std::str;

use tls_api::Result;
use tls_api::Error;
use webpki::DNSNameRef;
use rustls::NoClientAuth;


pub struct TlsConnectorBuilder {
    pub config: rustls::ClientConfig,
    pub verify_hostname: bool,
}
pub struct TlsConnector {
    pub config: Arc<rustls::ClientConfig>,
}

pub struct TlsAcceptorBuilder(pub rustls::ServerConfig);
pub struct TlsAcceptor(pub Arc<rustls::ServerConfig>);


pub struct TlsStream<S, T>
    where
        S : io::Read + io::Write + fmt::Debug + Send + 'static,
        T : rustls::Session + 'static,
{
    stream: S,
    session: T,
}

// TODO: do not require Sync from TlsStream
unsafe impl<S, T> Sync for TlsStream<S, T>
    where
        S : io::Read + io::Write + fmt::Debug + Send + 'static,
        T : rustls::Session + 'static,
{}

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


// TlsStream


impl<S, T> TlsStream<S, T>
    where
        S : io::Read + io::Write + fmt::Debug + Send + 'static,
        T : rustls::Session + 'static,
{
    fn complete_handshake(&mut self) -> result::Result<(), IntermediateError> {
        while self.session.is_handshaking() {
            // TODO: https://github.com/ctz/rustls/issues/77
            while self.session.is_handshaking() && self.session.wants_write() {
                self.session.write_tls(&mut self.stream)?;
            }
            if self.session.is_handshaking() && self.session.wants_read() {
                let r = self.session.read_tls(&mut self.stream)?;
                if r == 0 {
                    return Err(IntermediateError::Io(::std::io::Error::new(
                        ::std::io::ErrorKind::UnexpectedEof,
                        ::std::io::Error::new(::std::io::ErrorKind::Other, "closed mid handshake"),
                    )));
                }
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

impl<S, T> fmt::Debug for TlsStream<S, T>
    where
        S : io::Read + io::Write + fmt::Debug + Send + 'static,
        T : rustls::Session + 'static,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("TlsStream")
            .field("stream", &self.stream)
            .field("session", &"...")
            .finish()
    }
}

impl<S, T> io::Read for TlsStream<S, T>
    where
        S : io::Read + io::Write + fmt::Debug + Send + 'static,
        T : rustls::Session + 'static,
{
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        rustls::Stream { sock: &mut self.stream, sess: &mut self.session }
            .read(buf)
    }
}

impl<S, T> io::Write for TlsStream<S, T>
    where
        S : io::Read + io::Write + fmt::Debug + Send + 'static,
        T : rustls::Session + 'static,
{
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        rustls::Stream { sock: &mut self.stream, sess: &mut self.session }
            .write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        rustls::Stream { sock: &mut self.stream, sess: &mut self.session }
            .flush()
    }
}

impl<S, T> tls_api::TlsStreamImpl<S> for TlsStream<S, T>
    where
        S : io::Read + io::Write + fmt::Debug + Send + 'static,
        T : rustls::Session + 'static,
{
    fn shutdown(&mut self) -> io::Result<()> {
        // TODO: do something
        Ok(())
    }

    fn get_mut(&mut self) -> &mut S {
        &mut self.stream
    }

    fn get_ref(&self) -> &S {
        &self.stream
    }

    fn get_alpn_protocol(&self) -> Option<Vec<u8>> {
        self.session.get_alpn_protocol().map(Vec::from)
    }
}


// MidHandshakeTlsStream


pub struct MidHandshakeTlsStream<S, T>
    where
        S : io::Read + io::Write + fmt::Debug + Send + 'static,
        T : rustls::Session + 'static,
{
    stream: Option<TlsStream<S, T>>
}

impl<S, T> tls_api::MidHandshakeTlsStreamImpl<S> for MidHandshakeTlsStream<S, T>
    where
        S : io::Read + io::Write + fmt::Debug + Send + 'static,
        T : rustls::Session + 'static,
{
    fn handshake(&mut self) -> result::Result<tls_api::TlsStream<S>, tls_api::HandshakeError<S>> {
        self.stream.take().unwrap().complete_handleshake_mid()
    }
}

impl<T, S> fmt::Debug for MidHandshakeTlsStream<S, T>
    where
        S : io::Read + io::Write + fmt::Debug + Send + 'static,
        T : rustls::Session + 'static,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("MidHandshakeTlsStream")
            .field("stream", &self.stream)
            .finish()
    }
}



impl tls_api::TlsConnectorBuilder for TlsConnectorBuilder {
    type Connector = TlsConnector;

    type Underlying = rustls::ClientConfig;

    fn underlying_mut(&mut self) -> &mut rustls::ClientConfig {
        &mut self.config
    }

    fn add_root_certificate(&mut self, cert: tls_api::Certificate) -> Result<&mut Self> {
        match cert.format {
           tls_api::CertificateFormat::PEM => {
               let cert = rustls::internal::pemfile::certs(&mut cert.bytes.as_slice())
                   .map_err(|e| Error::new_other(&format!("{:?}", e)))?;
               if !cert.is_empty() {
                   self.config.root_store.add(&cert[0])
                       .map_err(|e| Error::new_other(&format!("{:?}", e)))?;
               }
           },
           tls_api::CertificateFormat::DER => {
               let cert = rustls::Certificate(cert.bytes);
               self.config.root_store.add(&cert)
                   .map_err(|e| Error::new_other(&format!("{:?}", e)))?;
           }
        }
        Ok(self)
    }

    fn supports_alpn() -> bool {
        true
    }

    fn set_alpn_protocols(&mut self, protocols: &[&[u8]]) -> Result<()> {
        self.config.alpn_protocols = protocols.into_iter().map(|p: &&[u8]| p.to_vec()).collect();
        Ok(())
    }

    fn build(mut self) -> Result<TlsConnector> {
        if self.config.root_store.is_empty() {
            self.config.root_store.add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);
        }
        Ok(TlsConnector {
            config: Arc::new(self.config),
        })
    }

    fn set_verify_hostname(&mut self, verify: bool) -> Result<()> {
        if !verify {
            struct NoCertificateVerifier;

            impl rustls::ServerCertVerifier for NoCertificateVerifier {
                fn verify_server_cert(
                    &self,
                    _roots: &rustls::RootCertStore,
                    _presented_certs: &[rustls::Certificate],
                    _dns_name: webpki::DNSNameRef,
                    _ocsp_response: &[u8])
                    -> result::Result<rustls::ServerCertVerified, rustls::TLSError>
                {
                    Ok(rustls::ServerCertVerified::assertion())
                }
            }

            self.config.dangerous().set_certificate_verifier(Arc::new(NoCertificateVerifier));
            self.verify_hostname = false;
        } else {
            if !self.verify_hostname {
                return Err(Error::new_other(
                    "cannot set_verify_hostname(true) after set_verify_hostname(false)"))
            }
        }

        Ok(())
    }
}

impl tls_api::TlsConnector for TlsConnector {
    type Builder = TlsConnectorBuilder;

    fn builder() -> Result<TlsConnectorBuilder> {
        Ok(TlsConnectorBuilder {
            config: rustls::ClientConfig::new(),
            verify_hostname: true,
        })
    }

    fn connect<S>(&self, domain: &str, stream: S)
        -> result::Result<tls_api::TlsStream<S>, tls_api::HandshakeError<S>>
            where S : io::Read + io::Write + fmt::Debug + Send + 'static
    {
        let dns_name = DNSNameRef::try_from_ascii_str(domain)
            .map_err(|()| tls_api::HandshakeError::Failure(tls_api::Error::new_other("invalid domain name")))?;
        let tls_stream = TlsStream {
            stream,
            session: rustls::ClientSession::new(&self.config, dns_name),
        };

        tls_stream.complete_handleshake_mid()
    }
}


// TlsAcceptor and TlsAcceptorBuilder


impl TlsAcceptorBuilder {
    pub fn from_certs_and_key(certs: &[&[u8]], key: &[u8]) -> Result<TlsAcceptorBuilder> {
        let mut config = rustls::ServerConfig::new(Arc::new(NoClientAuth));
        let certs = certs.into_iter().map(|c| rustls::Certificate(c.to_vec())).collect();
        config.set_single_cert(certs, rustls::PrivateKey(key.to_vec()))
            .map_err(tls_api::Error::new)?;
        Ok(TlsAcceptorBuilder(config))
    }
}

impl tls_api::TlsAcceptorBuilder for TlsAcceptorBuilder {
    type Acceptor = TlsAcceptor;

    type Underlying = rustls::ServerConfig;

    fn underlying_mut(&mut self) -> &mut rustls::ServerConfig {
        &mut self.0
    }

    fn supports_alpn() -> bool {
        // TODO: https://github.com/sfackler/rust-openssl/pull/646
        true
    }

    fn set_alpn_protocols(&mut self, protocols: &[&[u8]]) -> Result<()> {
        self.0.alpn_protocols = protocols.into_iter().map(|p| p.to_vec()).collect();
        Ok(())
    }

    fn build(self) -> Result<TlsAcceptor> {
        Ok(TlsAcceptor(Arc::new(self.0)))
    }
}

impl tls_api::TlsAcceptor for TlsAcceptor {
    type Builder = TlsAcceptorBuilder;

    fn accept<S>(&self, stream: S)
            -> result::Result<tls_api::TlsStream<S>, tls_api::HandshakeError<S>>
        where S : io::Read + io::Write + fmt::Debug + Send + 'static
    {
        let tls_stream = TlsStream {
            stream: stream,
            session: rustls::ServerSession::new(&self.0),
        };

        tls_stream.complete_handleshake_mid()
    }
}
