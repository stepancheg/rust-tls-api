mod handshake;
mod stream;

mod acceptor;
mod connector;

pub use acceptor::TlsAcceptor;
pub use acceptor::TlsAcceptorBuilder;
pub use connector::TlsConnector;
pub use connector::TlsConnectorBuilder;

pub(crate) use stream::TlsStream;

// TODO: https://github.com/sfackler/rust-openssl/pull/646
#[cfg(has_alpn)]
pub const HAS_ALPN: bool = true;
#[cfg(not(has_alpn))]
pub const HAS_ALPN: bool = false;

fn encode_alpn_protos(protos: &[&[u8]]) -> tls_api::Result<Vec<u8>> {
    let mut r = Vec::new();
    for proto in protos {
        if proto.len() > 255 {
            return Err(tls_api::Error::new_other("protocol len"));
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
