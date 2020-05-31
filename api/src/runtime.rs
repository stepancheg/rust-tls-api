#[cfg(feature = "runtime-async-std")]
pub use futures_util::io::{AsyncRead, AsyncWrite};

#[cfg(feature = "runtime-async-std")]
#[allow(unused_imports)]
pub use futures_util::io::{AsyncReadExt, AsyncWriteExt};

#[cfg(feature = "runtime-tokio")]
pub use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};