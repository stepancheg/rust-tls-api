use std::error;
use std::fmt;
use std::str::Utf8Error;

#[derive(Debug)]
pub(crate) enum Error {
    AlpnNotSupported,
    AlpnProtocolNotUtf8(Utf8Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::AlpnNotSupported => write!(f, "native-tls does not support ALPN"),
            Error::AlpnProtocolNotUtf8(error) => {
                write!(f, "given alpn protocol is not UTF-8: {}", error)
            }
        }
    }
}

impl error::Error for Error {}
