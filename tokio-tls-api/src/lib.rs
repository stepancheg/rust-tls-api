//! Async TLS streams
//!
//! This library is an implementation of TLS streams using the most appropriate
//! system library by default for negotiating the connection. That is, on
//! Windows this library uses SChannel, on OSX it uses SecureTransport, and on
//! other platforms it uses OpenSSL.
//!
//! Each TLS stream implements the `Read` and `Write` traits to interact and
//! interoperate with the rest of the futures I/O ecosystem. Client connections
//! initiated from this crate verify hostnames automatically and by default.
//!
//! This crate primarily exports this ability through two extension traits,
//! `TlsConnectorExt` and `TlsAcceptorExt`. These traits augment the
//! functionality provided by the `native-tls` crate, on which this crate is
//! built. Configuration of TLS parameters is still primarily done through the
//! `native-tls` crate.

#![deny(missing_docs)]
#![doc(html_root_url = "https://docs.rs/tokio-tls/0.1")]

#[cfg_attr(feature = "tokio-proto", macro_use)]
extern crate futures;
extern crate tls_api;
#[macro_use]
extern crate tokio_io;

use std::fmt;
use std::io::{self, Read, Write};

use futures::{Poll, Future, Async};
use tls_api::{HandshakeError, Error, TlsConnector, TlsAcceptor};
use tokio_io::{AsyncRead, AsyncWrite};

pub mod proto;

/// A wrapper around an underlying raw stream which implements the TLS or SSL
/// protocol.
///
/// A `TlsStream<S>` represents a handshake that has been completed successfully
/// and both the server and the client are ready for receiving and sending
/// data. Bytes read from a `TlsStream` are decrypted from `S` and bytes written
/// to a `TlsStream` are encrypted when passing through to `S`.
#[derive(Debug)]
pub struct TlsStream<S> {
    inner: tls_api::TlsStream<S>,
}

/// Future returned from `TlsConnectorExt::connect_async` which will resolve
/// once the connection handshake has finished.
pub struct ConnectAsync<S> {
    inner: MidHandshake<S>,
}

/// Future returned from `TlsAcceptorExt::accept_async` which will resolve
/// once the accept handshake has finished.
pub struct AcceptAsync<S> {
    inner: MidHandshake<S>,
}

struct MidHandshake<S> {
    inner: Option<Result<tls_api::TlsStream<S>, HandshakeError<S>>>,
}

impl<S> TlsStream<S> {
    /// Get access to the internal `tls_api::TlsStream` stream which also
    /// transitively allows access to `S`.
    pub fn get_ref(&self) -> &tls_api::TlsStream<S> {
        &self.inner
    }

    /// Get mutable access to the internal `tls_api::TlsStream` stream which
    /// also transitively allows mutable access to `S`.
    pub fn get_mut(&mut self) -> &mut tls_api::TlsStream<S> {
        &mut self.inner
    }
}

impl<S: Read + Write> Read for TlsStream<S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buf)
    }
}

impl<S: Read + Write> Write for TlsStream<S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl<S: AsyncRead + AsyncWrite> AsyncRead for TlsStream<S> {
}

impl<S: AsyncRead + AsyncWrite + 'static> AsyncWrite for TlsStream<S> {
    fn shutdown(&mut self) -> Poll<(), io::Error> {
        try_nb!(self.inner.shutdown());
        self.inner.get_mut().shutdown()
    }
}

/// Connects the provided stream with this connector, assuming the provided
/// domain.
///
/// This function will internally call `TlsConnector::connect` to connect
/// the stream and returns a future representing the resolution of the
/// connection operation. The returned future will resolve to either
/// `TlsStream<S>` or `Error` depending if it's successful or not.
///
/// This is typically used for clients who have already established, for
/// example, a TCP connection to a remote server. That stream is then
/// provided here to perform the client half of a connection to a
/// TLS-powered server.
///
/// # Compatibility notes
///
/// Note that this method currently requires `S: Read + Write` but it's
/// highly recommended to ensure that the object implements the `AsyncRead`
/// and `AsyncWrite` traits as well, otherwise this function will not work
/// properly.
pub fn connect_async<C, S>(connector: &C, domain: &str, stream: S) -> ConnectAsync<S>
    where
        S : io::Read + io::Write + fmt::Debug + Send + Sync + 'static,
        C : TlsConnector,
{
    ConnectAsync {
        inner: MidHandshake {
            inner: Some(connector.connect(domain, stream)),
        },
    }
}

/// Accepts a new client connection with the provided stream.
///
/// This function will internally call `TlsAcceptor::accept` to connect
/// the stream and returns a future representing the resolution of the
/// connection operation. The returned future will resolve to either
/// `TlsStream<S>` or `Error` depending if it's successful or not.
///
/// This is typically used after a new socket has been accepted from a
/// `TcpListener`. That socket is then passed to this function to perform
/// the server half of accepting a client connection.
///
/// # Compatibility notes
///
/// Note that this method currently requires `S: Read + Write` but it's
/// highly recommended to ensure that the object implements the `AsyncRead`
/// and `AsyncWrite` traits as well, otherwise this function will not work
/// properly.
pub fn accept_async<A, S>(acceptor: &A, stream: S) -> AcceptAsync<S>
    where
        S : io::Read + io::Write + fmt::Debug + Send + Sync + 'static,
        A : TlsAcceptor,
{
    AcceptAsync {
        inner: MidHandshake {
            inner: Some(acceptor.accept(stream)),
        },
    }
}

// TODO: change this to AsyncRead/AsyncWrite on next major version
impl<S: Read + Write + 'static> Future for ConnectAsync<S> {
    type Item = TlsStream<S>;
    type Error = Error;

    fn poll(&mut self) -> Poll<TlsStream<S>, Error> {
        self.inner.poll()
    }
}

// TODO: change this to AsyncRead/AsyncWrite on next major version
impl<S: Read + Write + 'static> Future for AcceptAsync<S> {
    type Item = TlsStream<S>;
    type Error = Error;

    fn poll(&mut self) -> Poll<TlsStream<S>, Error> {
        self.inner.poll()
    }
}

// TODO: change this to AsyncRead/AsyncWrite on next major version
impl<S: Read + Write + 'static> Future for MidHandshake<S> {
    type Item = TlsStream<S>;
    type Error = Error;

    fn poll(&mut self) -> Poll<TlsStream<S>, Error> {
        match self.inner.take().expect("cannot poll MidHandshake twice") {
            Ok(stream) => Ok(TlsStream { inner: stream }.into()),
            Err(HandshakeError::Failure(e)) => Err(e),
            Err(HandshakeError::Interrupted(s)) => {
                match s.handshake() {
                    Ok(stream) => Ok(TlsStream { inner: stream }.into()),
                    Err(HandshakeError::Failure(e)) => Err(e),
                    Err(HandshakeError::Interrupted(s)) => {
                        self.inner = Some(Err(HandshakeError::Interrupted(s)));
                        Ok(Async::NotReady)
                    }
                }
            }
        }
    }
}
