use std::error;
use std::fmt;

#[derive(Debug)]
pub(crate) enum Error {
    VerifyHostnameTrue,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::VerifyHostnameTrue => write!(
                f,
                "cannot set_verify_hostname(true) after set_verify_hostname(false)"
            ),
        }
    }
}

impl error::Error for Error {}

impl Into<tls_api::Error> for Error {
    fn into(self) -> tls_api::Error {
        tls_api::Error::new(self)
    }
}
