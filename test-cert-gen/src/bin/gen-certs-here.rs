use std::fs;

fn main() {
    let keys = test_cert_gen::gen_keys();

    fs::write("server.pem", keys.server.root_ca_pem.concat().concat()).unwrap();
    fs::write("server.pkcs12", &keys.server.root_ca_pkcs12.pkcs12.0).unwrap();
    fs::write(
        "server.pkcs12.password",
        &keys.server.root_ca_pkcs12.password,
    )
    .unwrap();

    fs::write("client.der", keys.client.cert_der.as_bytes()).unwrap();
}
