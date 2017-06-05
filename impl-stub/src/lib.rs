//! Stub implementation of TLS API.
//!
//! All operations return error. No objects can be instantiated.
//!
//! Can be useful when you need a type parameter of type e. g. `TlsConnector`:
//!
//! ```
//! use tls_api_stub::TlsConnector;
//!
//! let no_connector: Option<TlsConnector> = None;
//! ```

extern crate tls_api;
extern crate void;

use std::io;
use std::result;
use std::fmt;
use std::error::Error as std_Error;

use void::Void;

use tls_api::Result;


pub struct Pkcs12(Void);
pub struct Certificate(Void);

pub struct TlsConnectorBuilder(Void);
pub struct TlsConnector(Void);

pub struct TlsAcceptorBuilder(Void);
pub struct TlsAcceptor(Void);

#[derive(Debug)]
struct Error;

impl std_Error for Error {
    fn description(&self) -> &str {
        "stub implementation"
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(self.description(), f)
    }
}

impl tls_api::Pkcs12 for Pkcs12 {
    fn from_der(_der: &[u8], _password: &str) -> Result<Self> {
        Err(tls_api::Error::new(Error))
    }
}

impl tls_api::Certificate for Certificate {
    fn from_der(_der: &[u8]) -> Result<Self> where Self: Sized {
        Err(tls_api::Error::new(Error))
    }
}

impl tls_api::TlsConnectorBuilder for TlsConnectorBuilder {
    type Connector = TlsConnector;

    type Underlying = Void;

    fn underlying_mut(&mut self) -> &mut Void {
        &mut self.0
    }

    fn add_root_certificate(&mut self, _cert: Certificate) -> Result<&mut Self> {
        Err(tls_api::Error::new(Error))
    }

    fn build(self) -> Result<TlsConnector> {
        Err(tls_api::Error::new(Error))
    }
}

impl tls_api::TlsConnector for TlsConnector {
    type Builder = TlsConnectorBuilder;
    type Certificate = Certificate;

    fn builder() -> Result<TlsConnectorBuilder> {
        Err(tls_api::Error::new(Error))
    }

    fn connect<S>(&self, _domain: &str, _stream: S)
        -> result::Result<tls_api::TlsStream<S>, tls_api::HandshakeError<S>>
            where S: io::Read + io::Write + fmt::Debug + 'static
    {
        Err(tls_api::HandshakeError::Failure(tls_api::Error::new(Error)))
    }

    fn danger_connect_without_providing_domain_for_certificate_verification_and_server_name_indication<S>(
        &self,
        _stream: S)
        -> result::Result<tls_api::TlsStream<S>, tls_api::HandshakeError<S>>
            where S: io::Read + io::Write + fmt::Debug + 'static
    {
        Err(tls_api::HandshakeError::Failure(tls_api::Error::new(Error)))
    }
}

impl tls_api::TlsAcceptorBuilder for TlsAcceptorBuilder {
    type Acceptor = TlsAcceptor;

    type Underlying = Void;

    fn underlying_mut(&mut self) -> &mut Void {
        &mut self.0
    }

    fn build(self) -> Result<TlsAcceptor> {
        Err(tls_api::Error::new(Error))
    }
}

impl tls_api::TlsAcceptor for TlsAcceptor {
    type Pkcs12 = Pkcs12;
    type Builder = TlsAcceptorBuilder;

    fn builder(_pkcs12: Pkcs12) -> Result<TlsAcceptorBuilder> {
        Err(tls_api::Error::new(Error))
    }

    fn accept<S>(&self, _stream: S)
            -> result::Result<tls_api::TlsStream<S>, tls_api::HandshakeError<S>>
        where S: io::Read + io::Write + fmt::Debug + 'static
    {
        Err(tls_api::HandshakeError::Failure(tls_api::Error::new(Error)))
    }
}
