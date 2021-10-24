// Error

use crate::TlsAcceptorType;
use std::error;
use std::fmt;

/// Some error types used by tls-api implementations.
#[derive(Debug)]
pub(crate) enum CommonError {
    /// TlsBuilder cannot be constructed from PKCS #12 or DER key.
    TlsBuilderFromFromDerOrPkcs12NotSupported(&'static dyn TlsAcceptorType),
    OpensslCommandFailedToConvert,
    PemFromPkcs12ContainsNotSingleCertKeyPair(Vec<String>),
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
