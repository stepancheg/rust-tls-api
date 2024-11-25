//! Common implementation of tests for all TLS API implementations.
//!
//! Common tests are written here and executed in impl-crates.
//!
//! Probably you don't need this crate outside of `rust-tls-api` repository.

#![feature(test)]

#[macro_use]
extern crate log;

extern crate test;

use std::any;
use std::str;

#[macro_use]
mod t;

mod alpn;
pub mod benches;
mod client_server;
mod client_server_dyn;
mod google;
mod version;

pub use alpn::test_alpn;
pub use client_server::test_client_server_der;
pub use client_server::test_client_server_pkcs12;
pub use client_server_dyn::test_client_server_dyn_der;
pub use client_server_dyn::test_client_server_dyn_pkcs12;
pub use google::test_google;
pub use version::test_version;

mod gen;
pub use gen::gen_tests_and_benches;

use tls_api::TlsAcceptor;
use tls_api::TlsAcceptorBox;
use tls_api::TlsAcceptorBuilder;
use tls_api::TlsAcceptorBuilderBox;
use tls_api::TlsAcceptorType;
use tls_api::TlsConnector;
use tls_api::TlsConnectorBox;
use tls_api::TlsConnectorBuilder;
use tls_api::TlsConnectorBuilderBox;
use tls_api::TlsConnectorType;

use std::net::ToSocketAddrs;

#[cfg(feature = "runtime-async-std")]
pub use async_std::net::TcpListener;
#[cfg(feature = "runtime-async-std")]
pub use async_std::net::TcpStream;

#[cfg(feature = "runtime-tokio")]
pub use tokio::net::TcpListener;
#[cfg(feature = "runtime-tokio")]
pub use tokio::net::TcpStream;

#[cfg(feature = "runtime-async-std")]
pub use async_std::task::block_on;

#[cfg(feature = "runtime-tokio")]
pub fn block_on<F, T>(future: F) -> T
where
    F: std::future::Future<Output = T>,
{
    t!(tokio::runtime::Runtime::new()).block_on(future)
}

async fn connect_bad_hostname_impl<C: TlsConnector, F: FnOnce(anyhow::Error)>(check_error: F) {
    drop(env_logger::try_init());

    if !C::IMPLEMENTED {
        eprintln!(
            "connector {} is not implemented; skipping",
            any::type_name::<C>()
        );
        return;
    }

    // First up, resolve google.com
    let addr = t!("google.com:443".to_socket_addrs()).next().unwrap();

    let connector: C = C::builder().expect("builder").build().expect("build");
    let tcp_stream = t!(TcpStream::connect(addr).await);
    let error = connector
        .connect("goggle.com", tcp_stream)
        .await
        .unwrap_err();
    check_error(error);
}

pub fn connect_bad_hostname<C: TlsConnector, F: FnOnce(anyhow::Error)>(check_error: F) {
    block_on(connect_bad_hostname_impl::<C, F>(check_error))
}

async fn connect_bad_hostname_ignored_impl<C: TlsConnector>() {
    drop(env_logger::try_init());

    if !C::IMPLEMENTED {
        eprintln!(
            "connector {} is not implemented; skipping",
            any::type_name::<C>()
        );
        return;
    }

    // First up, resolve google.com
    let addr = t!("google.com:443".to_socket_addrs()).next().unwrap();

    let tcp_stream = t!(TcpStream::connect(addr).await);

    let mut builder = C::builder().expect("builder");
    builder
        .set_verify_hostname(false)
        .expect("set_verify_hostname");
    let connector: C = builder.build().expect("build");
    t!(connector.connect("ignore", tcp_stream).await);
}

pub fn connect_bad_hostname_ignored<C: TlsConnector>() {
    block_on(connect_bad_hostname_ignored_impl::<C>())
}

fn new_acceptor_builder_from_pkcs12_keys<A>() -> A::Builder
where
    A: TlsAcceptor,
{
    t!(A::builder_from_pkcs12(
        &test_cert_gen::keys().server.cert_and_key_pkcs12.pkcs12.0,
        &test_cert_gen::keys().server.cert_and_key_pkcs12.password,
    ))
}

fn new_acceptor_builder_from_der_keys<A>() -> A::Builder
where
    A: TlsAcceptor,
{
    let keys = &test_cert_gen::keys().server.cert_and_key;
    t!(A::builder_from_der_key(
        keys.cert.get_der(),
        keys.key.get_der()
    ))
}

#[allow(dead_code)]
fn new_acceptor_from_der_keys<A: TlsAcceptor>() -> A {
    new_acceptor_builder_from_der_keys::<A>().build().unwrap()
}

fn new_acceptor_builder_dyn_from_pkcs12_keys(
    acceptor: &dyn TlsAcceptorType,
) -> TlsAcceptorBuilderBox {
    t!(acceptor.builder_from_pkcs12(
        &test_cert_gen::keys().server.cert_and_key_pkcs12.pkcs12.0,
        &test_cert_gen::keys().server.cert_and_key_pkcs12.password,
    ))
}

fn new_acceptor_builder_dyn_from_der_keys(acceptor: &dyn TlsAcceptorType) -> TlsAcceptorBuilderBox {
    let keys = &test_cert_gen::keys().server.cert_and_key;
    t!(acceptor.builder_from_der_key(keys.cert.get_der(), keys.key.get_der()))
}

#[allow(dead_code)]
fn new_acceptor_dyn_from_der_keys(acceptor: &dyn TlsAcceptorType) -> TlsAcceptorBox {
    new_acceptor_builder_dyn_from_der_keys(acceptor)
        .build()
        .unwrap()
}

pub enum AcceptorKeyKind {
    Pkcs12,
    Der,
}

fn new_acceptor<A>(key: Option<AcceptorKeyKind>) -> A::Builder
where
    A: TlsAcceptor,
{
    match key {
        Some(AcceptorKeyKind::Der) => new_acceptor_builder_from_der_keys::<A>(),
        Some(AcceptorKeyKind::Pkcs12) => new_acceptor_builder_from_pkcs12_keys::<A>(),
        None => {
            if A::SUPPORTS_PKCS12_KEYS {
                new_acceptor_builder_from_pkcs12_keys::<A>()
            } else if A::SUPPORTS_DER_KEYS {
                new_acceptor_builder_from_der_keys::<A>()
            } else {
                panic!(
                    "no constructor supported for acceptor {}",
                    any::type_name::<A>()
                );
            }
        }
    }
}

fn new_acceptor_dyn(
    acceptor: &dyn TlsAcceptorType,
    key: Option<AcceptorKeyKind>,
) -> TlsAcceptorBuilderBox {
    match key {
        Some(AcceptorKeyKind::Der) => new_acceptor_builder_dyn_from_der_keys(acceptor),
        Some(AcceptorKeyKind::Pkcs12) => new_acceptor_builder_dyn_from_pkcs12_keys(acceptor),
        None => {
            if acceptor.supports_pkcs12_keys() {
                new_acceptor_builder_dyn_from_pkcs12_keys(acceptor)
            } else if acceptor.supports_der_keys() {
                new_acceptor_builder_dyn_from_der_keys(acceptor)
            } else {
                panic!("no constructor supported for acceptor {}", acceptor);
            }
        }
    }
}

fn new_connector_builder_with_root_ca<C: TlsConnector>() -> C::Builder {
    let keys = test_cert_gen::keys();
    let root_ca = &keys.client.ca;

    let mut connector = C::builder().expect("connector builder");
    t!(connector.add_root_certificate(root_ca.get_der()));
    connector
}

fn new_connector_with_root_ca<C: TlsConnector>() -> C {
    new_connector_builder_with_root_ca::<C>().build().unwrap()
}

fn new_connector_builder_dyn_with_root_ca(
    connector: &dyn TlsConnectorType,
) -> TlsConnectorBuilderBox {
    let keys = test_cert_gen::keys();
    let root_ca = &keys.client.ca;

    let mut connector = connector.builder().expect("connector builder");
    t!(connector.add_root_certificate(root_ca.get_der()));
    connector
}

#[allow(dead_code)]
fn new_connector_dyn_with_root_ca(connector: &dyn TlsConnectorType) -> TlsConnectorBox {
    new_connector_builder_dyn_with_root_ca(connector)
        .build()
        .unwrap()
}

// `::1` is broken on travis-ci
// https://travis-ci.org/stepancheg/rust-tls-api/jobs/312681800
pub const BIND_HOST: &str = "127.0.0.1";
