use std::fs;

fn main() {
    let keys = test_cert_gen_2::gen_keys();

    println!("writing server cert to server.pem");
    fs::write("server.pem", keys.server.cert_and_key.to_pem_incorrect()).unwrap();

    println!("writing root ca to ca.der");
    fs::write("ca.der", keys.client.ca.get_der()).unwrap();
    println!("writing root ca to ca.pem");
    fs::write("ca.pem", keys.client.ca.to_pem()).unwrap();
}
