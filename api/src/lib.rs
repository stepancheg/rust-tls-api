use std::io;


pub trait Pkcs12 {
}

pub trait Certificate {
    type Error;

    fn from_der(der: &[u8]) -> Result<Self, Self::Error> where Self : Sized;
}

pub trait TlsConnectorBuilder : Sized {
    type Connector : TlsConnector;

    fn add_root_certificate(&mut self, cert: <Self::Connector as TlsConnector>::Certificate)
        -> Result<&mut Self, <Self::Connector as TlsConnector>::Error>;

    fn build(self) -> Result<Self::Connector, <Self::Connector as TlsConnector>::Error>;
}

pub trait TlsStream : io::Read + io::Write {
}

/// An error returned from `ClientBuilder::handshake`.
#[derive(Debug)]
pub enum HandshakeError<E, S : MidHandshakeTlsStream> {
    /// A fatal error.
    Failure(E),

    /// A stream interrupted midway through the handshake process due to a
    /// `WouldBlock` error.
    ///
    /// Note that this is not a fatal error and it should be safe to call
    /// `handshake` at a later time once the stream is ready to perform I/O
    /// again.
    Interrupted(S),
}

pub trait MidHandshakeTlsStream : Sized {
    type Error;
    type TlsStream : TlsStream;

    fn handshake(self) -> Result<Self::TlsStream, HandshakeError<Self::Error, Self>>;
}

pub trait TlsConnector : Sized {
    type Builder : TlsConnectorBuilder;
    type Error;
    type Certificate : Certificate;
    type Pkcs12 : Pkcs12;
    type TlsStream : TlsStream;
    type MidHandshakeTlsStream : MidHandshakeTlsStream<TlsStream=Self::TlsStream>;

    fn builder() -> Result<Self::Builder, Self::Error>;

    fn connect<S>(
        &self,
        domain: &str,
        stream: S)
            -> Result<Self::TlsStream, HandshakeError<Self::Error, Self::MidHandshakeTlsStream>>
        where S : io::Read + io::Write + 'static;

}

pub trait TlsAcceptorBuilder : Sized {
    type Acceptor : TlsAcceptor;

    fn build(self) -> Result<Self::Acceptor, <Self::Acceptor as TlsAcceptor>::Error>;
}

pub trait TlsAcceptor : Sized {
    type Error;
    type Pkcs12 : Pkcs12;
    type Builder : TlsAcceptorBuilder;
    type TlsStream : TlsStream;
    type MidHandshakeTlsStream : MidHandshakeTlsStream<TlsStream=Self::TlsStream>;

    fn builder(pkcs12: Self::Pkcs12) -> Result<Self::Builder, Self::Error>;

    fn accept<S>(&self, stream: S)
            -> Result<Self::TlsStream, HandshakeError<Self::Error, Self::MidHandshakeTlsStream>>
        where S : io::Read + io::Write + 'static;
}
