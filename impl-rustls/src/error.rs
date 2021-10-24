#[derive(Debug, thiserror::Error)]
pub(crate) enum Error {
    #[error("cannot set_verify_hostname(true) after set_verify_hostname(false)")]
    VerifyHostnameTrue,
}
