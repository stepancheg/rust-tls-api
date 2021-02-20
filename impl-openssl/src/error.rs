use std::error;
use std::fmt;

#[derive(Debug)]
pub(crate) enum Error {
    #[allow(dead_code)]
    CompiledWithoutAlpn,
    AlpnProtocolLen,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::CompiledWithoutAlpn => write!(f, "openssl is compiled without ALPN"),
            Error::AlpnProtocolLen => write!(f, "incorrect ALPN protocol name length"),
        }
    }
}

impl error::Error for Error {}

impl Into<tls_api::Error> for Error {
    fn into(self) -> tls_api::Error {
        tls_api::Error::new(self)
    }
}
