#[derive(Debug, thiserror::Error)]
pub(crate) enum Error {
    #[error("ALPN makes no sense for not-tls implementation")]
    Alpn,
}
