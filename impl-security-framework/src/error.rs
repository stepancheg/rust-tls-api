use std::error;
use std::fmt;
use std::str::Utf8Error;

#[derive(Debug)]
pub(crate) enum Error {
    AlpnOnServer,
    IdentitiesNotFoundInPkcs12,
    MoreThanOneIdentityInPkcs12(u32),
    NotIosOrMacos,
    TooManyAlpnProtocols(Vec<String>),
    ReturnedAlpnProtocolIsNotUtf8(Utf8Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::AlpnOnServer => write!(
                f,
                "security-framework does not support ALPN on the server side"
            ),
            Error::IdentitiesNotFoundInPkcs12 => write!(f, "identities not found in PKCS #12 file"),
            Error::MoreThanOneIdentityInPkcs12(count) => {
                write!(f, "{} identities found in PKCS #12 file", count)
            }
            Error::NotIosOrMacos => write!(
                f,
                "security-framework is not available on non-iOS and non-macOS"
            ),
            Error::TooManyAlpnProtocols(protocols) => write!(
                f,
                "security-framework returned more than one negotiated ALPN protocols: {:?}",
                protocols
            ),
            Error::ReturnedAlpnProtocolIsNotUtf8(error) => {
                write!(f, "returned ALPN protocol is not UTF-8: {}", error)
            }
        }
    }
}

impl error::Error for Error {}

impl Into<tls_api::Error> for Error {
    fn into(self) -> tls_api::Error {
        tls_api::Error::new(self)
    }
}
