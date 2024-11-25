//! Utilities to generate keys for tests.
//!
//! Uses OpenSSL command line utility to generate the certificates.

use std::fs;
use std::io::Read;
use std::io::Write;
use std::process::Command;
use std::process::Stdio;

use tempfile::Builder as TempBuilder;

pub use cert::pem_to_cert_key_pair;
pub use cert::Cert;
pub use cert::Pkcs12;
pub use cert::Pkcs12AndPassword;
pub use cert::PrivateKey;
use once_cell::sync::Lazy;

mod cert;

#[derive(Debug, PartialEq, Clone)]
pub struct CertAndPrivateKey {
    pub cert: Cert,
    pub key: PrivateKey,
}

impl CertAndPrivateKey {
    /// Incorrect because key is serialized incorrectly
    pub fn to_pem_incorrect(&self) -> String {
        self.cert.to_pem() + &self.key.to_pem_incorrect()
    }
}

/// Client certificate
pub struct ClientKeys {
    pub ca: Cert,
}

/// Server keys
pub struct ServerKeys {
    /// Server certificate
    pub cert_and_key_pkcs12: Pkcs12AndPassword,

    /// Server certificate
    pub cert_and_key: CertAndPrivateKey,
}

/// Client and server keys
pub struct Keys {
    /// Client keys
    pub client: ClientKeys,
    /// Server keys
    pub server: ServerKeys,
}

fn gen_root_ca() -> CertAndPrivateKey {
    let temp_dir = TempBuilder::new()
        .prefix("rust-test-cert-gen-gen-root-ca")
        .tempdir()
        .unwrap();

    let config = temp_dir.path().join("openssl.config");
    let keyfile = temp_dir.path().join("root_ca.key");
    let certfile = temp_dir.path().join("root_ca.crt");

    fs::write(
        &config,
        b"\
                [req]\n\
                distinguished_name=dn\n\
                [dn]\n\
                CN=my.ca\n\
                [ext]\n\
                basicConstraints=CA:TRUE,pathlen:0\n\
                subjectAltName = @alt_names\n\
                extendedKeyUsage=serverAuth,clientAuth\n\
                [alt_names]\n\
                DNS.1 = my.ca\n\
            ",
    )
    .unwrap();

    let subj = "/C=US/ST=Denial/L=Sprintfield/O=Dis/CN=my.ca";
    // Making root CA
    let gen_ca = Command::new("openssl")
        .arg("req")
        .arg("-nodes")
        .arg("-x509")
        .args(["-newkey", "rsa:2048"])
        .arg("-config")
        .arg(&config)
        .args(["-extensions", "ext"])
        .arg("-subj")
        .arg(subj)
        .arg("-keyout")
        .arg(&keyfile)
        .arg("-out")
        .arg(&certfile)
        .args(["-days", "1"])
        // TODO: print on error
        // .stderr(Stdio::inherit())
        .output()
        .unwrap();
    assert!(gen_ca.status.success());

    let cert = fs::read_to_string(&certfile).unwrap();
    let key = fs::read_to_string(&keyfile).unwrap();

    assert_eq!(1, pem::parse_many(cert.as_bytes()).unwrap().len());
    assert_eq!(1, pem::parse_many(key.as_bytes()).unwrap().len());

    CertAndPrivateKey {
        cert: Cert::from_pem(&cert).unwrap(),
        key: PrivateKey::from_pem(&key).unwrap(),
    }
}

fn gen_cert_for_domain(domain: &str, ca: &CertAndPrivateKey) -> CertAndPrivateKey {
    assert!(!domain.is_empty());

    let temp_dir = TempBuilder::new().prefix("pem-to-der").tempdir().unwrap();
    let privkey_pem_path = temp_dir.path().join("privkey.pem");
    let csr = temp_dir.path().join("csr.pem");
    let ca_pem = temp_dir.path().join("ca.pem");
    let ca_key_path = temp_dir.path().join("ca-key.pem");
    let cert_path = temp_dir.path().join("cert.pem");
    let conf_path = temp_dir.path().join("conf");
    let conf2_path = temp_dir.path().join("conf2");

    fs::write(&ca_pem, ca.cert.to_pem()).unwrap();
    fs::write(&ca_key_path, ca.key.to_pem_incorrect()).unwrap();

    assert!(Command::new("openssl")
        .arg("genrsa")
        .arg("-out")
        .arg(&privkey_pem_path)
        .arg("2048")
        .output()
        .unwrap()
        .status
        .success());

    fs::write(
        &conf_path,
        format!(
            "\
            [req]\n\
            req_extensions = v3_req\n\
            distinguished_name = req_distinguished_name\n\
            [v3_req]\n\
            basicConstraints = CA:FALSE\n\
            keyUsage = digitalSignature, keyEncipherment\n\
            extendedKeyUsage = serverAuth\n\
            subjectAltName = DNS.0:{}\n\
            [req_distinguished_name]\n\
            # empty\n\
        ",
            domain
        ),
    )
    .unwrap();

    // CSR
    assert!(Command::new("openssl")
        .arg("req")
        .arg("-new")
        .arg("-key")
        .arg(&privkey_pem_path)
        .arg("-sha256")
        .arg("-out")
        .arg(&csr)
        .args([
            "-subj",
            &format!("/C=US/ST=Utah/L=Provo/O=ACME Service/CN={}", domain)
        ])
        .arg("-config")
        .arg(&conf_path)
        .stderr(Stdio::inherit())
        .output()
        .unwrap()
        .status
        .success());

    fs::write(
        &conf2_path,
        format!(
            "\
                subjectAltName = DNS.0:{}\n\
                extendedKeyUsage = serverAuth\n\
              ",
            domain
        ),
    )
    .unwrap();

    // Sign the request from Server with your Root CA
    assert!(Command::new("openssl")
        .arg("x509")
        .arg("-req")
        .arg("-in")
        .arg(&csr)
        .arg("-CA")
        .arg(&ca_pem)
        .arg("-CAkey")
        .arg(&ca_key_path)
        .arg("-CAcreateserial")
        .arg("-extfile")
        .arg(&conf2_path)
        .arg("-out")
        .arg(&cert_path)
        .args(["-days", "1"])
        .arg("-sha256")
        .output()
        .unwrap()
        .status
        .success());

    let key = fs::read_to_string(&privkey_pem_path).unwrap();
    let cert = fs::read_to_string(&cert_path).unwrap();

    // verify
    assert_eq!(1, pem::parse_many(cert.as_bytes()).unwrap().len());
    assert_eq!(1, pem::parse_many(key.as_bytes()).unwrap().len());

    CertAndPrivateKey {
        cert: Cert::from_pem(&cert).unwrap(),
        key: PrivateKey::from_pem(&key).unwrap(),
    }
}

pub fn gen_keys() -> Keys {
    let root_ca_pem = gen_root_ca();

    let server_cert_pem = gen_cert_for_domain("localhost", &root_ca_pem);

    let server_cert_pkcs12 = pem_to_pkcs12_some_password(&server_cert_pem);

    Keys {
        client: ClientKeys {
            ca: root_ca_pem.cert,
        },
        server: ServerKeys {
            cert_and_key: server_cert_pem,
            cert_and_key_pkcs12: server_cert_pkcs12,
        },
    }
}

/// Generate keys
pub fn keys() -> &'static Keys {
    static KEYS: Lazy<Keys> = Lazy::new(gen_keys);
    &KEYS
}

fn _pkcs12_to_pem(pkcs12: &Pkcs12, passin: &str) -> String {
    let mut command = Command::new("openssl")
        .arg("pkcs12")
        .args(["-passin", &format!("pass:{}", passin)])
        .arg("-nodes")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();

    command
        .stdin
        .as_mut()
        .unwrap()
        .write_all(&pkcs12.0)
        .unwrap();

    let mut pem = String::new();
    command
        .stdout
        .as_mut()
        .unwrap()
        .read_to_string(&mut pem)
        .unwrap();

    assert!(command.wait().unwrap().success());

    pem
}

fn pem_to_pkcs12(cert: &CertAndPrivateKey, pass: &str) -> Pkcs12 {
    let temp_dir = TempBuilder::new()
        .prefix("pem-to-pkcs12")
        .tempdir()
        .unwrap();

    let certfile = temp_dir.path().join("cert.pem");
    let keyfile = temp_dir.path().join("key.pem");

    fs::write(&certfile, cert.cert.to_pem()).unwrap();
    fs::write(&keyfile, cert.key.to_pem_incorrect()).unwrap();

    let pkcs12out = Command::new("openssl")
        .arg("pkcs12")
        .arg("-export")
        .arg("-descert")
        .arg("-inkey")
        .arg(&keyfile)
        .arg("-in")
        .arg(&certfile)
        .args(["-password", &format!("pass:{}", pass)])
        .output()
        .unwrap();
    assert!(pkcs12out.status.success());
    Pkcs12(pkcs12out.stdout)
}

fn pem_to_pkcs12_some_password(cert: &CertAndPrivateKey) -> Pkcs12AndPassword {
    let password = "serp".to_owned();
    let pkcs12 = pem_to_pkcs12(cert, &password);
    Pkcs12AndPassword { pkcs12, password }
}

#[cfg(test)]
mod test {
    use crate::gen_keys;
    use std::fs;
    use std::io::BufRead;
    use std::io::BufReader;
    use std::io::Write;
    use std::process::Command;
    use std::process::Stdio;
    use std::sync::mpsc;
    use std::thread;

    use tempfile::Builder as TempBuilder;

    #[test]
    fn test() {
        // just check it does something
        super::keys();
    }

    #[test]
    fn verify() {
        let temp_dir = TempBuilder::new().prefix("t").tempdir().unwrap();

        let keys = gen_keys();

        let ca_pem = temp_dir.path().join("ca.pem");
        let server_pem = temp_dir.path().join("server.pem");

        fs::write(&ca_pem, keys.client.ca.to_pem()).unwrap();
        fs::write(&server_pem, keys.server.cert_and_key.to_pem_incorrect()).unwrap();

        // error is, what does it mean?
        // ```
        // error 18 at 0 depth lookup:self signed certificate
        // ```
        let status = Command::new("openssl")
            .arg("verify")
            .arg("-CAfile")
            .arg(&ca_pem)
            .arg(&server_pem)
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap()
            .wait()
            .unwrap();
        assert!(status.success())
    }

    #[test]
    #[ignore] // TODO: hangs on CI
    fn client_server() {
        let temp_dir = TempBuilder::new()
            .prefix("client_server")
            .tempdir()
            .unwrap();

        let keys = gen_keys();

        let client = temp_dir.path().join("client");
        let server = temp_dir.path().join("server.pem");

        fs::write(client, keys.client.ca.get_der()).unwrap();
        fs::write(&server, keys.server.cert_and_key.to_pem_incorrect()).unwrap();

        let port = 1234;

        let mut s_server = Command::new("openssl")
            .arg("s_server")
            .arg("-accept")
            .arg(port.to_string())
            .arg("-cert")
            .arg(&server)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();

        let (signal_tx, signal_rx) = mpsc::channel();

        let client = thread::spawn(move || {
            let mut s_client = Command::new("openssl")
                .arg("s_client")
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .arg("-connect")
                .arg(format!("localhost:{}", port))
                .arg("-verify_return_error")
                .spawn()
                .unwrap();
            s_client
                .stdin
                .as_mut()
                .unwrap()
                .write_all(b"ping\n")
                .unwrap();
            let _ = signal_rx.recv();
            s_client.kill().unwrap();
        });

        let lines = BufReader::new(s_server.stdout.as_mut().unwrap()).lines();
        for line in lines {
            let line = line.unwrap();
            println!("> {}", line);
            if line == "ping" {
                break;
            }
        }

        s_server.kill().unwrap();
        let _ = signal_tx.send(());
        client.join().unwrap();
    }
}
