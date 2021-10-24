// Error

use crate::TlsAcceptorType;

/// Some error types used by tls-api implementations.
#[derive(Debug, thiserror::Error)]
pub(crate) enum CommonError {
    /// TlsBuilder cannot be constructed from PKCS #12 or DER key.
    #[error(
        "implementation {} does not support construction from neither DER nor PKCS #12 keys",
        _0
    )]
    TlsBuilderFromFromDerOrPkcs12NotSupported(&'static dyn TlsAcceptorType),
    #[error("openssl command to convert certificate failed")]
    OpensslCommandFailedToConvert,
    #[error("PEM file created from PKCS #12 is expected to contain a single certificate and key, it actually contains {:?}", _0)]
    PemFromPkcs12ContainsNotSingleCertKeyPair(Vec<String>),
}
