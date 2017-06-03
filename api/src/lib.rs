use std::io;
use std::fmt;
use std::error;
use std::result;


pub trait Pkcs12 {
}

pub struct Error(Box<error::Error>);

impl Error {
    pub fn new<E : error::Error + 'static>(e: E) -> Error {
        Error(Box::new(e))
    }
}

impl error::Error for Error {
    fn description(&self) -> &str {
        self.0.description()
    }

    fn cause(&self) -> Option<&error::Error> {
        self.0.cause()
    }
}

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(&self.0, f)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

pub type Result<A> = result::Result<A, Error>;



pub trait Certificate {
    fn from_der(der: &[u8]) -> Result<Self> where Self : Sized;
}

pub trait TlsConnectorBuilder : Sized {
    type Connector : TlsConnector;

    fn add_root_certificate(&mut self, cert: <Self::Connector as TlsConnector>::Certificate)
        -> Result<&mut Self>;

    fn build(self) -> Result<Self::Connector>;
}

pub trait TlsStream : io::Read + io::Write {
}

/// An error returned from `ClientBuilder::handshake`.
#[derive(Debug)]
pub enum HandshakeError<S : MidHandshakeTlsStream> {
    /// A fatal error.
    Failure(Error),

    /// A stream interrupted midway through the handshake process due to a
    /// `WouldBlock` error.
    ///
    /// Note that this is not a fatal error and it should be safe to call
    /// `handshake` at a later time once the stream is ready to perform I/O
    /// again.
    Interrupted(S),
}

pub trait MidHandshakeTlsStream : Sized {
    type TlsStream : TlsStream;

    fn handshake(self) -> result::Result<Self::TlsStream, HandshakeError<Self>>;
}

pub trait TlsConnector : Sized {
    type Builder : TlsConnectorBuilder;
    type Certificate : Certificate;
    type Pkcs12 : Pkcs12;
    type TlsStream : TlsStream;
    type MidHandshakeTlsStream : MidHandshakeTlsStream<TlsStream=Self::TlsStream>;

    fn builder() -> Result<Self::Builder>;

    fn connect<S>(
        &self,
        domain: &str,
        stream: S)
            -> result::Result<Self::TlsStream, HandshakeError<Self::MidHandshakeTlsStream>>
        where S : io::Read + io::Write + 'static;

}

pub trait TlsAcceptorBuilder : Sized {
    type Acceptor : TlsAcceptor;

    fn build(self) -> Result<Self::Acceptor>;
}

pub trait TlsAcceptor : Sized {
    type Pkcs12 : Pkcs12;
    type Builder : TlsAcceptorBuilder;
    type TlsStream : TlsStream;
    type MidHandshakeTlsStream : MidHandshakeTlsStream<TlsStream=Self::TlsStream>;

    fn builder(pkcs12: Self::Pkcs12) -> Result<Self::Builder>;

    fn accept<S>(&self, stream: S)
            -> result::Result<Self::TlsStream, HandshakeError<Self::MidHandshakeTlsStream>>
        where S : io::Read + io::Write + 'static;
}
