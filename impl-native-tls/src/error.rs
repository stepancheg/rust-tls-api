use std::str::Utf8Error;

#[derive(Debug, thiserror::Error)]
pub(crate) enum Error {
    #[error("native-tls does not support ALPN")]
    AlpnNotSupported,
    #[error("given alpn protocol is not UTF-8: {}", _0)]
    AlpnProtocolNotUtf8(Utf8Error),
}
