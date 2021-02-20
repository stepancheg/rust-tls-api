use std::any;

pub fn test_version<C: tls_api::TlsConnector, A: tls_api::TlsAcceptor>() {
    eprintln!(
        "connector {} '{}' supports_alpn={}",
        any::type_name::<A>(),
        A::info(),
        A::SUPPORTS_ALPN
    );
    eprintln!(
        "acceptor {} '{}' supports_alpn={}",
        any::type_name::<C>(),
        C::info(),
        C::SUPPORTS_ALPN
    );
}
