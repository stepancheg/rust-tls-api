use std::io;
use std::fmt;
use std::error;
use std::result;

pub mod impl_test;


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



pub trait TlsStreamImpl: io::Read + io::Write + fmt::Debug {
}

/// Since Rust has no HKT, it is not possible to declare something like
///
/// ```ignore
/// trait TlsConnector {
///     type <S> TlsStream<S> : TlsStreamImpl;
/// }
/// ```
#[derive(Debug)]
pub struct TlsStream(Box<TlsStreamImpl>);

impl TlsStream {
    pub fn new<S : TlsStreamImpl + 'static>(stream: S) -> TlsStream {
        TlsStream(Box::new(stream))
    }
}

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



pub trait MidHandshakeTlsStreamImpl : fmt::Debug {
    fn handshake(&mut self) -> result::Result<TlsStream, HandshakeError>;
}

#[derive(Debug)]
pub struct MidHandshakeTlsStream(Box<MidHandshakeTlsStreamImpl>);

impl MidHandshakeTlsStream {
    pub fn new<S : MidHandshakeTlsStreamImpl + 'static>(stream: S) -> MidHandshakeTlsStream {
        MidHandshakeTlsStream(Box::new(stream))
    }

    pub fn handshake(mut self) -> result::Result<TlsStream, HandshakeError> {
        self.0.handshake()
    }
}



/// An error returned from `ClientBuilder::handshake`.
#[derive(Debug)]
pub enum HandshakeError {
    /// A fatal error.
    Failure(Error),

    /// A stream interrupted midway through the handshake process due to a
    /// `WouldBlock` error.
    ///
    /// Note that this is not a fatal error and it should be safe to call
    /// `handshake` at a later time once the stream is ready to perform I/O
    /// again.
    Interrupted(MidHandshakeTlsStream),
}


pub trait TlsConnector : Sized {
    type Builder : TlsConnectorBuilder<Connector=Self>;
    type Certificate : Certificate;
    type Pkcs12 : Pkcs12;

    fn builder() -> Result<Self::Builder>;

    fn connect<S>(
        &self,
        domain: &str,
        stream: S)
            -> result::Result<TlsStream, HandshakeError>
        where S : io::Read + io::Write + fmt::Debug + 'static;

    fn danger_connect_without_providing_domain_for_certificate_verification_and_server_name_indication<S>(
        &self,
        stream: S)
            -> result::Result<TlsStream, HandshakeError>
        where S : io::Read + io::Write + fmt::Debug + 'static;
}

pub trait TlsAcceptorBuilder : Sized {
    type Acceptor : TlsAcceptor;

    fn build(self) -> Result<Self::Acceptor>;
}

pub trait TlsAcceptor : Sized {
    type Pkcs12 : Pkcs12;
    type Builder : TlsAcceptorBuilder;

    fn builder(pkcs12: Self::Pkcs12) -> Result<Self::Builder>;

    fn accept<S>(&self, stream: S)
            -> result::Result<TlsStream, HandshakeError>
        where S : io::Read + io::Write + fmt::Debug + 'static;
}
