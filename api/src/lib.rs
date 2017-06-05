//! Implementation neutral TLS API.

use std::io;
use std::fmt;
use std::error;
use std::result;


pub struct Error(Box<error::Error + Send + Sync>);

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Error {
        Error::new(err)
    }
}

/// An error returned from the TLS implementation.
impl Error {
    pub fn new<E : error::Error + 'static + Send + Sync>(e: E) -> Error {
        Error(Box::new(e))
    }

    pub fn into_inner(self) -> Box<error::Error + Send + Sync> {
        self.0
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


/// A typedef of the result type returned by many methods.
pub type Result<A> = result::Result<A, Error>;


pub trait Pkcs12 : Sized {
    fn from_der(der: &[u8], password: &str) -> Result<Self>;
}


pub trait Certificate {
    fn from_der(der: &[u8]) -> Result<Self> where Self : Sized;
}


pub trait TlsStreamImpl<S> : io::Read + io::Write + fmt::Debug + Send + Sync + 'static {
    fn shutdown(&mut self) -> io::Result<()>;

    fn get_mut(&mut self) -> &mut S;
}

/// Since Rust has no HKT, it is not possible to declare something like
///
/// ```ignore
/// trait TlsConnector {
///     type <S> TlsStream<S> : TlsStreamImpl;
/// }
///
/// So `TlsStream` is actually a box to concrete TLS implementation.
/// ```
#[derive(Debug)]
pub struct TlsStream<S>(Box<TlsStreamImpl<S> + 'static>);

impl<S : 'static> TlsStream<S> {
    pub fn new<I : TlsStreamImpl<S> + 'static>(imp: I) -> TlsStream<S> {
        TlsStream(Box::new(imp))
    }

    pub fn shutdown(&mut self) -> io::Result<()> {
        self.0.shutdown()
    }

    pub fn get_mut(&mut self) -> &mut S {
        self.0.get_mut()
    }
}

impl<S> io::Read for TlsStream<S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf)
    }
}

impl<S> io::Write for TlsStream<S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}



pub trait MidHandshakeTlsStreamImpl<S> : fmt::Debug + Sync + Send + 'static {
    fn handshake(&mut self) -> result::Result<TlsStream<S>, HandshakeError<S>>;
}

#[derive(Debug)]
pub struct MidHandshakeTlsStream<S>(Box<MidHandshakeTlsStreamImpl<S> + 'static>);

impl<S : 'static> MidHandshakeTlsStream<S> {
    pub fn new<I : MidHandshakeTlsStreamImpl<S> + 'static>(stream: I) -> MidHandshakeTlsStream<S> {
        MidHandshakeTlsStream(Box::new(stream))
    }

    pub fn handshake(mut self) -> result::Result<TlsStream<S>, HandshakeError<S>> {
        self.0.handshake()
    }
}



/// An error returned from `ClientBuilder::handshake`.
#[derive(Debug)]
pub enum HandshakeError<S> {
    /// A fatal error.
    Failure(Error),

    /// A stream interrupted midway through the handshake process due to a
    /// `WouldBlock` error.
    ///
    /// Note that this is not a fatal error and it should be safe to call
    /// `handshake` at a later time once the stream is ready to perform I/O
    /// again.
    Interrupted(MidHandshakeTlsStream<S>),
}


/// A builder for `TlsConnector`s.
pub trait TlsConnectorBuilder : Sized + Sync + Send + 'static {
    type Connector : TlsConnector;

    fn add_root_certificate(&mut self, cert: <Self::Connector as TlsConnector>::Certificate)
        -> Result<&mut Self>;

    fn build(self) -> Result<Self::Connector>;
}


/// A builder for client-side TLS connections.
pub trait TlsConnector : Sized + Sync + Send + 'static {
    type Builder : TlsConnectorBuilder<Connector=Self>;
    type Certificate : Certificate;

    fn builder() -> Result<Self::Builder>;

    fn connect<S>(
        &self,
        domain: &str,
        stream: S)
            -> result::Result<TlsStream<S>, HandshakeError<S>>
        where S : io::Read + io::Write + fmt::Debug + Send + Sync + 'static;

    fn danger_connect_without_providing_domain_for_certificate_verification_and_server_name_indication<S>(
        &self,
        stream: S)
            -> result::Result<TlsStream<S>, HandshakeError<S>>
        where S : io::Read + io::Write + fmt::Debug + Send + Sync + 'static;
}

/// A builder for `TlsAcceptor`s.
pub trait TlsAcceptorBuilder : Sized + Sync + Send + 'static {
    type Acceptor : TlsAcceptor;

    fn build(self) -> Result<Self::Acceptor>;
}

/// A builder for server-side TLS connections.
pub trait TlsAcceptor : Sized + Sync + Send + 'static {
    type Pkcs12 : Pkcs12;
    type Builder : TlsAcceptorBuilder<Acceptor=Self>;

    fn builder(pkcs12: Self::Pkcs12) -> Result<Self::Builder>;

    fn accept<S>(&self, stream: S)
            -> result::Result<TlsStream<S>, HandshakeError<S>>
        where S : io::Read + io::Write + fmt::Debug + Send + Sync + 'static;
}

fn _check_kinds() {
    use std::net::TcpStream;

    fn is_sync<T : Sync>() {}
    fn is_send<T : Send>() {}
    is_sync::<Error>();
    is_send::<Error>();
    is_sync::<TlsStream<TcpStream>>();
    is_send::<TlsStream<TcpStream>>();
    is_sync::<MidHandshakeTlsStream<TcpStream>>();
    is_send::<MidHandshakeTlsStream<TcpStream>>();
}
