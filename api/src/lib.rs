use std::io;
use std::fmt;
use std::error;
use std::result;

pub mod impl_test;


pub struct Error(Box<error::Error + Send + Sync>);

impl Error {
    pub fn new<E : error::Error + 'static + Send + Sync>(e: E) -> Error {
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


pub trait Pkcs12 : Sized {
    fn from_der(der: &[u8], password: &str) -> Result<Self>;
}


pub trait Certificate {
    fn from_der(der: &[u8]) -> Result<Self> where Self : Sized;
}

pub trait TlsStreamImpl<S>: io::Read + io::Write + fmt::Debug {
    fn shutdown(&mut self) -> io::Result<()>;

    fn get_mut(&mut self) -> &mut S;
}

/// Since Rust has no HKT, it is not possible to declare something like
///
/// ```ignore
/// trait TlsConnector {
///     type <S> TlsStream<S> : TlsStreamImpl;
/// }
/// ```
#[derive(Debug)]
pub struct TlsStream<S>(Box<TlsStreamImpl<S>>);

impl<S> TlsStream<S> {
    pub fn new<I: TlsStreamImpl<S> + 'static>(imp: I) -> TlsStream<S> {
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



pub trait MidHandshakeTlsStreamImpl<S> : fmt::Debug {
    fn handshake(&mut self) -> result::Result<TlsStream<S>, HandshakeError<S>>;
}

#[derive(Debug)]
pub struct MidHandshakeTlsStream<S>(Box<MidHandshakeTlsStreamImpl<S>>);

impl<S> MidHandshakeTlsStream<S> {
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


pub trait TlsConnectorBuilder : Sized {
    type Connector : TlsConnector;
    type Certificate : Certificate;

    fn new() -> Result<Self>;

    fn add_root_certificate(&mut self, cert: Self::Certificate)
        -> Result<&mut Self>;

    fn build(self) -> Result<Self::Connector>;
}

pub trait TlsConnector : Send + 'static {
    fn connect<S>(
        &self,
        domain: &str,
        stream: S)
            -> result::Result<TlsStream<S>, HandshakeError<S>>
        where S : io::Read + io::Write + fmt::Debug + 'static;

    fn danger_connect_without_providing_domain_for_certificate_verification_and_server_name_indication<S>(
        &self,
        stream: S)
            -> result::Result<TlsStream<S>, HandshakeError<S>>
        where S : io::Read + io::Write + fmt::Debug + 'static;
}

pub trait TlsAcceptorBuilder : Sized {
    type Acceptor : TlsAcceptor;

    fn build(self) -> Result<Self::Acceptor>;
}

pub trait TlsAcceptor : Sized + Send + 'static {
    type Pkcs12 : Pkcs12;
    type Builder : TlsAcceptorBuilder<Acceptor=Self>;

    fn builder(pkcs12: Self::Pkcs12) -> Result<Self::Builder>;

    fn accept<S>(&self, stream: S)
            -> result::Result<TlsStream<S>, HandshakeError<S>>
        where S : io::Read + io::Write + fmt::Debug + 'static;
}
