// Error

use std::error;
use std::fmt;
use std::io;
use std::result;

pub struct Error(Box<dyn error::Error + Send + Sync + 'static>);

/// An error returned from the TLS implementation.
impl Error {
    pub fn new<E: error::Error + 'static + Send + Sync>(e: E) -> Error {
        Error(Box::new(e))
    }

    pub fn new_other(message: &str) -> Error {
        Self::new(io::Error::new(io::ErrorKind::Other, message))
    }

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
