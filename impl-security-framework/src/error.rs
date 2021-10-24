use std::str::Utf8Error;

#[derive(Debug, thiserror::Error)]
pub(crate) enum Error {
    #[error("security-framework does not support ALPN on the server side")]
    AlpnOnServer,
    #[error("identities not found in PKCS #12 file")]
    IdentitiesNotFoundInPkcs12,
    #[error("{} identities found in PKCS #12 file", _0)]
    MoreThanOneIdentityInPkcs12(u32),
    #[error("security-framework is not available on non-iOS and non-macOS")]
    NotIosOrMacos,
    #[error(
        "security-framework returned more than one negotiated ALPN protocols: {:?}",
        _0
    )]
    TooManyAlpnProtocols(Vec<String>),
    #[error("returned ALPN protocol is not UTF-8: {}", _0)]
    ReturnedAlpnProtocolIsNotUtf8(Utf8Error),
}
