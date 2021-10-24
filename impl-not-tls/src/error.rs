use std::error;
use std::fmt;

#[derive(Debug)]
pub(crate) enum Error {
    Alpn,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Alpn => write!(f, "ALPN makes no sense for not-tls implementation"),
        }
    }
}

impl error::Error for Error {}
