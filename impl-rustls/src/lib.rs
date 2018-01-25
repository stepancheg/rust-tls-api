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
use rustls::Session;

pub struct TlsConnectorBuilder(pub rustls::ClientConfig);
pub struct TlsConnector(pub Arc<rustls::ClientConfig>);

pub struct TlsAcceptorBuilder(pub rustls::ServerConfig);
pub struct TlsAcceptor(pub Arc<rustls::ServerConfig>);


pub struct TlsStream<S, T>
    where
        S : io::Read + io::Write + fmt::Debug + Send + 'static,
        T : rustls::Session + 'static,
{
    stream: S,
    session: T,
    // Amount of data buffered in session
    write_skip: usize,
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
        let r = self.session.read(buf)?;
        if r > 0 {
            return Ok(r);
        }

        loop {
            self.session.read_tls(&mut self.stream)?;
            self.session.process_new_packets()
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
            match self.session.read(buf) {
                Ok(0) => {
                    // No plaintext available yet.
                    continue;
                }
                rc @ _ => return rc
            };
        }
    }
}

impl<S, T> io::Write for TlsStream<S, T>
    where
        S : io::Read + io::Write + fmt::Debug + Send + 'static,
        T : rustls::Session + 'static,
{
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut rd_offset = self.write_skip;
        let mut nsent = 0;
        loop {
            let wrote = if rd_offset < buf.len() {
                self.session.write(&buf[rd_offset..])?
            } else { 0 };
            self.write_skip += wrote;
            rd_offset += wrote;
            if self.write_skip > 0 {
                loop {
                    match self.session.write_tls(&mut self.stream) {
                        Ok(0) => {
                            return Ok(0);
                        }
                        Ok(_) => { // we can not rely on returned bytes, as TLS adds its own data
                            if !self.session.wants_write() {
                                nsent += self.write_skip;
                                self.write_skip = 0;
                            }
                            break;
                        }
                        Err(e) => {
                            if e.kind() == ::std::io::ErrorKind::Interrupted {
                                continue;
                            } else if e.kind() == ::std::io::ErrorKind::WouldBlock {
                                if nsent == 0 {
                                    return Err(e);
                                } else {
                                    return Ok(nsent);
                                }
                            }
                            return Err(e);
                        }
                    }
                }
            } else {
                break;
            }
        }
        Ok(nsent)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.session.flush()?;
        self.session.write_tls(&mut self.stream)?;
        Ok(())
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
        self.session.get_alpn_protocol().map(|s| Vec::from(s.as_bytes()))
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
        &mut self.0
    }

    fn add_root_certificate(&mut self, cert: tls_api::Certificate) -> Result<&mut Self> {
        let cert = rustls::Certificate(cert.into_der());
        self.0.root_store.add(&cert)
            .map_err(|e| Error::new_other(&format!("{:?}", e)))?;
        Ok(self)
    }

    fn supports_alpn() -> bool {
        true
    }

    fn set_alpn_protocols(&mut self, protocols: &[&[u8]]) -> Result<()> {
        let mut v = Vec::new();
        for p in protocols {
            v.push(String::from(str::from_utf8(p).map_err(Error::new)?));
        }
        self.0.alpn_protocols = v;
        Ok(())
    }

    fn build(mut self) -> Result<TlsConnector> {
        if self.0.root_store.is_empty() {
            self.0.root_store.add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);
        }
        Ok(TlsConnector(Arc::new(self.0)))
    }
}

impl tls_api::TlsConnector for TlsConnector {
    type Builder = TlsConnectorBuilder;

    fn builder() -> Result<TlsConnectorBuilder> {
        Ok(TlsConnectorBuilder(rustls::ClientConfig::new()))
    }

    fn connect<S>(&self, domain: &str, stream: S)
        -> result::Result<tls_api::TlsStream<S>, tls_api::HandshakeError<S>>
            where S : io::Read + io::Write + fmt::Debug + Send + 'static
    {
        if let Ok(domain) = webpki::DNSNameRef::try_from_ascii_str(domain) {
            let mut tls_stream = TlsStream {
                stream,
                session: rustls::ClientSession::new(&self.0, domain),
                write_skip: 0,
            };
            tls_stream.session.set_buffer_limit(16*1024);

            return tls_stream.complete_handleshake_mid();
        }
        Err(tls_api::HandshakeError::Failure(Error::new_other("invalid domain")))
    }

    fn danger_connect_without_providing_domain_for_certificate_verification_and_server_name_indication<S>(
        &self,
        stream: S)
        -> result::Result<tls_api::TlsStream<S>, tls_api::HandshakeError<S>>
            where S : io::Read + io::Write + fmt::Debug + Send + 'static
    {
        // TODO: Clone current config: https://github.com/ctz/rustls/pull/78
        let mut client_config = rustls::ClientConfig::new();

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

        client_config.dangerous().set_certificate_verifier(Arc::new(NoCertificateVerifier));

        let tls_stream = if let Ok(domain) = webpki::DNSNameRef::try_from_ascii_str("ignore") {
            let mut session = rustls::ClientSession::new(&Arc::new(client_config), domain);
            session.set_buffer_limit(16*1024);
            TlsStream {
                stream: stream,
                session,
                write_skip: 0,
            }
        } else {
            return Err(tls_api::HandshakeError::Failure(Error::new_other("invalid domain")));
        };

        tls_stream.complete_handleshake_mid()
    }
}


// TlsAcceptor and TlsAcceptorBuilder


impl TlsAcceptorBuilder {
    pub fn from_certs_and_key(certs: &[&[u8]], key: &[u8]) -> Result<TlsAcceptorBuilder> {
        let mut config = rustls::ServerConfig::new(rustls::NoClientAuth::new());
        let certs = certs.into_iter().map(|c| rustls::Certificate(c.to_vec())).collect();
        config.set_single_cert(certs, rustls::PrivateKey(key.to_vec()));
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
        let mut v = Vec::new();
        for p in protocols {
            v.push(String::from(str::from_utf8(p).map_err(Error::new)?));
        }
        self.0.alpn_protocols = v;
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
        let mut tls_stream = TlsStream {
            stream: stream,
            session: rustls::ServerSession::new(&self.0),
            write_skip: 0,
        };
        tls_stream.session.set_buffer_limit(16*1024);

        tls_stream.complete_handleshake_mid()
    }
}

