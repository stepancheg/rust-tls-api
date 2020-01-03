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

use std::error::Error as std_Error;
use std::fmt;

use void::Void;

use std::future::Future;
use std::pin::Pin;
use tls_api::Result;
use tls_api::TlsStream;
use tokio::io::AsyncRead;
use tokio::io::AsyncWrite;

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
        write!(f, "stub implementation")
    }
}

impl tls_api::TlsConnectorBuilder for TlsConnectorBuilder {
    type Connector = TlsConnector;

    type Underlying = Void;

    fn underlying_mut(&mut self) -> &mut Void {
        &mut self.0
    }

    fn supports_alpn() -> bool {
        false
    }

    fn set_alpn_protocols(&mut self, _protocols: &[&[u8]]) -> Result<()> {
        Err(tls_api::Error::new(Error))
    }

    fn set_verify_hostname(&mut self, _verify: bool) -> Result<()> {
        Err(tls_api::Error::new(Error))
    }

    fn add_root_certificate(&mut self, _cert: tls_api::Certificate) -> Result<&mut Self> {
        Err(tls_api::Error::new(Error))
    }

    fn build(self) -> Result<TlsConnector> {
        Err(tls_api::Error::new(Error))
    }
}

impl tls_api::TlsConnector for TlsConnector {
    type Builder = TlsConnectorBuilder;

    fn builder() -> Result<TlsConnectorBuilder> {
        Err(tls_api::Error::new(Error))
    }

    fn connect<'a, S>(
        &'a self,
        _domain: &'a str,
        _stream: S,
    ) -> Pin<Box<dyn Future<Output = tls_api::Result<TlsStream<S>>> + Send + 'a>>
    where
        S: AsyncRead + AsyncWrite + fmt::Debug + Unpin + Send + Sync + 'static,
    {
        Box::pin(async { Err(tls_api::Error::new(Error)) })
    }
}

impl tls_api::TlsAcceptorBuilder for TlsAcceptorBuilder {
    type Acceptor = TlsAcceptor;

    type Underlying = Void;

    fn supports_alpn() -> bool {
        false
    }

    fn set_alpn_protocols(&mut self, _protocols: &[&[u8]]) -> Result<()> {
        Err(tls_api::Error::new(Error))
    }

    fn underlying_mut(&mut self) -> &mut Void {
        &mut self.0
    }

    fn build(self) -> Result<TlsAcceptor> {
        Err(tls_api::Error::new(Error))
    }
}

impl tls_api::TlsAcceptor for TlsAcceptor {
    type Builder = TlsAcceptorBuilder;

    fn accept<'a, S>(
        &'a self,
        _stream: S,
    ) -> Pin<Box<dyn Future<Output = Result<TlsStream<S>>> + Send + 'a>>
    where
        S: AsyncRead + AsyncWrite + fmt::Debug + Unpin + Send + Sync + 'static,
    {
        Box::pin(async { Err(tls_api::Error::new(Error)) })
    }
}
