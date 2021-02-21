//! Tokio or async-std type reexports.

#[cfg(feature = "runtime-async-std")]
pub use futures_util::io::AsyncRead;
#[cfg(feature = "runtime-async-std")]
pub use futures_util::io::AsyncReadExt;
#[cfg(feature = "runtime-async-std")]
pub use futures_util::io::AsyncWrite;
#[cfg(feature = "runtime-async-std")]
pub use futures_util::io::AsyncWriteExt;

#[cfg(feature = "runtime-tokio")]
pub use tokio::io::AsyncRead;
#[cfg(feature = "runtime-tokio")]
pub use tokio::io::AsyncReadExt;
#[cfg(feature = "runtime-tokio")]
pub use tokio::io::AsyncWrite;
#[cfg(feature = "runtime-tokio")]
pub use tokio::io::AsyncWriteExt;
#[cfg(feature = "runtime-tokio")]
pub use tokio::io::ReadBuf;
