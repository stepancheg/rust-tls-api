#[derive(Debug, thiserror::Error)]
pub(crate) enum Error {
    #[allow(dead_code)]
    #[error("openssl is compiled without ALPN")]
    CompiledWithoutAlpn,
    #[error("incorrect ALPN protocol name length")]
    AlpnProtocolLen,
}
