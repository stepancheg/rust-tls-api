use std::error;
use std::fmt;

#[derive(Debug)]
pub(crate) enum Error {
    AlpnNotSupported,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "native-tls does not support ALPN")
    }
}

impl error::Error for Error {}

impl Into<tls_api::Error> for Error {
    fn into(self) -> tls_api::Error {
        tls_api::Error::new(self)
    }
}
