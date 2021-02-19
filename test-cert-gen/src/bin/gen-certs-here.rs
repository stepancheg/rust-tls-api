use std::fs;

fn main() {
    let keys = test_cert_gen::gen_keys();

    println!("writing server cert to server.pem");
    fs::write(
        "server.pem",
        keys.server.server_cert_and_key.to_pem_incorrect(),
    )
    .unwrap();

    println!("writing root ca to ca.der");
    fs::write("ca.der", keys.client.ca_der.get_der()).unwrap();
    println!("writing root ca to ca.pem");
    fs::write("ca.pem", keys.client.ca_der.to_pem()).unwrap();
}
