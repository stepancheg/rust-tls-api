// Error

use crate::TlsAcceptorType;
use std::error;
use std::fmt;
use std::io;
use std::result;

/// Some error types used by tls-api implementations.
#[derive(Debug)]
pub(crate) enum CommonError {
    /// TlsBuilder cannot be constructed from PKCS #12 or DER key.
    TlsBuilderFromFromDerOrPkcs12NotSupported(&'static dyn TlsAcceptorType),
    OpensslCommandFailedToConvert,
    PemFromPkcs12ContainsNotSingleCertKeyPair(Vec<String>),
}

impl From<CommonError> for Error {
    fn from(e: CommonError) -> Self {
        Error::new(e)
    }
}

impl fmt::Display for CommonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CommonError::TlsBuilderFromFromDerOrPkcs12NotSupported(t) =>
                write!(f, "implementation {} does not support construction from neither DER nor PKCS #12 keys", t),
            CommonError::OpensslCommandFailedToConvert => write!(f, "openssl command to convert certificate failed"),
            CommonError::PemFromPkcs12ContainsNotSingleCertKeyPair(tags) => write!(f, "PEM file created from PKCS #12 is expected to contain a single certificate and key, it actually contains {:?}", tags)
        }
    }
}

impl error::Error for CommonError {}

/// Error returned by virtually all operations of this crate.
pub struct Error(Box<dyn error::Error + Send + Sync + 'static>);

/// An error returned from the TLS implementation.
impl Error {
    /// Construct an error by wrapping another error.
    pub fn new<E: error::Error + 'static + Send + Sync>(e: E) -> Error {
        Error(Box::new(e))
    }

    /// Unwrap the error.
    pub fn into_inner(self) -> Box<dyn error::Error + Send + Sync> {
        self.0
    }
}

impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        self.0.source()
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

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Error {
        Error::new(err)
    }
}

impl From<Error> for io::Error {
    fn from(err: Error) -> io::Error {
        io::Error::new(io::ErrorKind::Other, err)
    }
}

// Result

/// A typedef of the result type returned by many methods.
pub type Result<A> = result::Result<A, Error>;
