use rustls::ClientConnection;
use rustls::ServerConnection;
use rustls::StreamOwned;
use std::fmt::Arguments;
use std::io;
use std::io::IoSlice;
use std::io::IoSliceMut;
use std::io::Read;
use std::io::Write;
use tls_api::async_as_sync::WriteShutdown;

pub enum RustlsSessionRef<'a> {
    Client(&'a ClientConnection),
    Server(&'a ServerConnection),
}

/// Merge client and server stream into single interface
pub(crate) enum RustlsStream<S: Read + Write> {
    Server(StreamOwned<ServerConnection, S>),
    Client(StreamOwned<ClientConnection, S>),
}

impl<S: Read + Write> RustlsStream<S> {
    pub fn session(&self) -> RustlsSessionRef {
        match self {
            RustlsStream::Server(s) => RustlsSessionRef::Server(&s.conn),
            RustlsStream::Client(s) => RustlsSessionRef::Client(&s.conn),
        }
    }
}

impl<S: Read + Write> RustlsStream<S> {
    pub fn get_socket_mut(&mut self) -> &mut S {
        match self {
            RustlsStream::Server(s) => s.get_mut(),
            RustlsStream::Client(s) => s.get_mut(),
        }
    }

    pub fn get_socket_ref(&self) -> &S {
        match self {
            RustlsStream::Server(s) => s.get_ref(),
            RustlsStream::Client(s) => s.get_ref(),
        }
    }

    pub fn is_handshaking(&self) -> bool {
        match self {
            RustlsStream::Server(s) => s.conn.is_handshaking(),
            RustlsStream::Client(s) => s.conn.is_handshaking(),
        }
    }

    pub fn complete_io(&mut self) -> io::Result<(usize, usize)> {
        match self {
            RustlsStream::Server(s) => s.conn.complete_io(&mut s.sock),
            RustlsStream::Client(s) => s.conn.complete_io(&mut s.sock),
        }
    }

    pub fn get_alpn_protocol(&self) -> Option<&[u8]> {
        match self {
            RustlsStream::Server(s) => s.conn.alpn_protocol(),
            RustlsStream::Client(s) => s.conn.alpn_protocol(),
        }
    }
}

impl<S: Read + Write> Write for RustlsStream<S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            RustlsStream::Server(s) => s.write(buf),
            RustlsStream::Client(s) => s.write(buf),
        }
    }

    fn write_vectored(&mut self, bufs: &[IoSlice<'_>]) -> io::Result<usize> {
        match self {
            RustlsStream::Server(s) => s.write_vectored(bufs),
            RustlsStream::Client(s) => s.write_vectored(bufs),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            RustlsStream::Server(s) => s.flush(),
            RustlsStream::Client(s) => s.flush(),
        }
    }

    fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        match self {
            RustlsStream::Server(s) => s.write_all(buf),
            RustlsStream::Client(s) => s.write_all(buf),
        }
    }

    fn write_fmt(&mut self, fmt: Arguments<'_>) -> io::Result<()> {
        match self {
            RustlsStream::Server(s) => s.write_fmt(fmt),
            RustlsStream::Client(s) => s.write_fmt(fmt),
        }
    }
}

impl<S: Read + Write> WriteShutdown for RustlsStream<S> {
    fn shutdown(&mut self) -> Result<(), io::Error> {
        match self {
            RustlsStream::Server(s) => s.conn.send_close_notify(),
            RustlsStream::Client(s) => s.conn.send_close_notify(),
        }
        self.flush()?;
        Ok(())
    }
}

impl<S: Read + Write> Read for RustlsStream<S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            RustlsStream::Server(s) => s.read(buf),
            RustlsStream::Client(s) => s.read(buf),
        }
    }

    fn read_vectored(&mut self, bufs: &mut [IoSliceMut<'_>]) -> io::Result<usize> {
        match self {
            RustlsStream::Server(s) => s.read_vectored(bufs),
            RustlsStream::Client(s) => s.read_vectored(bufs),
        }
    }

    fn read_to_end(&mut self, buf: &mut Vec<u8>) -> io::Result<usize> {
        match self {
            RustlsStream::Server(s) => s.read_to_end(buf),
            RustlsStream::Client(s) => s.read_to_end(buf),
        }
    }

    fn read_to_string(&mut self, buf: &mut String) -> io::Result<usize> {
        match self {
            RustlsStream::Server(s) => s.read_to_string(buf),
            RustlsStream::Client(s) => s.read_to_string(buf),
        }
    }

    fn read_exact(&mut self, buf: &mut [u8]) -> io::Result<()> {
        match self {
            RustlsStream::Server(s) => s.read_exact(buf),
            RustlsStream::Client(s) => s.read_exact(buf),
        }
    }
}
