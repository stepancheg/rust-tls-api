use std::fmt::Write;

use std::env;
use std::fs;

fn main() {
    let out_dir = env::var("OUT_DIR").unwrap();

    let impls = &["native_tls", "rustls", "openssl", "security_framework"];

    let mut client_server = String::new();
    for client in impls {
        for server in impls {
            writeln!(client_server, "#[test]").unwrap();
            writeln!(client_server, "fn {}_{}_der() {{", client, server).unwrap();
            writeln!(client_server, "  tls_api_test::client_server_der::<tls_api_{}::TlsConnector, tls_api_{}::TlsAcceptor>();", client, server).unwrap();
            writeln!(client_server, "}}").unwrap();
            writeln!(client_server, "#[test]").unwrap();
            writeln!(client_server, "fn {}_{}_pkcs12() {{", client, server).unwrap();
            writeln!(client_server, "  tls_api_test::client_server_pkcs12::<tls_api_{}::TlsConnector, tls_api_{}::TlsAcceptor>();", client, server).unwrap();
            writeln!(client_server, "}}").unwrap();
        }
    }

    let mut alpn = String::new();
    for client in impls {
        for server in impls {
            writeln!(alpn, "#[test]").unwrap();
            writeln!(alpn, "fn {}_{}() {{", client, server).unwrap();
            writeln!(
                alpn,
                "  tls_api_test::alpn::<tls_api_{}::TlsConnector, tls_api_{}::TlsAcceptor>();",
                client, server
            )
            .unwrap();
            writeln!(alpn, "}}").unwrap();
        }
    }

    fs::write(format!("{}/client_server.rs", out_dir), &client_server).unwrap();
    fs::write(format!("{}/alpn.rs", out_dir), &alpn).unwrap();
}
