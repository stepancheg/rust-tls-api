//! [`tls_api`] implementation for [`openssl`].

#![deny(rustdoc::broken_intra_doc_links)]

mod acceptor;
mod connector;
mod error;
mod handshake;
mod stream;

pub use acceptor::TlsAcceptor;
pub use acceptor::TlsAcceptorBuilder;
pub use connector::TlsConnector;
pub use connector::TlsConnectorBuilder;

pub(crate) use error::Error;
pub(crate) use stream::TlsStream;

use tls_api::ImplInfo;

// TODO: https://github.com/sfackler/rust-openssl/pull/646
#[cfg(has_alpn)]
pub(crate) const HAS_ALPN: bool = true;
#[cfg(not(has_alpn))]
pub(crate) const HAS_ALPN: bool = false;

fn encode_alpn_protos(protos: &[&[u8]]) -> anyhow::Result<Vec<u8>> {
    let mut r = Vec::new();
    for proto in protos {
        if proto.len() > 255 {
            return Err(crate::Error::AlpnProtocolLen.into());
        }
        r.push(proto.len() as u8);
        r.extend_from_slice(proto);
    }
    Ok(r)
}

#[cfg(test)]
#[test]
fn test_encode_alpn_protos() {
    assert_eq!(
        &b"\x06spdy/1\x08http/1.1"[..],
        &encode_alpn_protos(&[b"spdy/1", b"http/1.1"]).unwrap()[..]
    );
}

pub(crate) fn into() -> ImplInfo {
    ImplInfo {
        name: "openssl",
        version: openssl::version::version(),
    }
}
