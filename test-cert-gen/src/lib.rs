//! Utilities to generate keys for tests.
//!
//! This is copy-paste from tokio-tls.

use std::fs;
use std::io::Read;
use std::io::Write;
use std::process::Command;
use std::process::Stdio;
use std::ptr;
use std::sync::Once;
use tls_api::Pem;
use tls_api::Pkcs12;
use tls_api::Pkcs12AndPassword;
use tls_api::X509Cert;

#[derive(Debug, PartialEq, Clone)]
pub struct CertAndKeyPem {
    pub cert: Pem,
    pub key: Pem,
}

impl CertAndKeyPem {
    pub fn concat(&self) -> Pem {
        &self.cert + &self.key
    }
}

/// Client certificate
pub struct ClientKeys {
    pub cert_der: X509Cert,
}

/// Server keys
pub struct ServerKeys {
    /// Certificate and key
    pub root_ca_pkcs12: Pkcs12AndPassword,

    /// The same in PEM format
    pub root_ca_pem: CertAndKeyPem,

    /// Server certificate
    pub server_cert_pem: CertAndKeyPem,
}

/// Client and server keys
pub struct Keys {
    /// Client keys
    pub client: ClientKeys,
    /// Server keys
    pub server: ServerKeys,
}

fn gen_root_ca() -> CertAndKeyPem {
    let temp_dir = tempdir::TempDir::new("rust-test-cert-gen-gen-root-ca").unwrap();

    let config = temp_dir.path().join("openssl.config");
    let keyfile = temp_dir.path().join("root_ca.key");
    let certfile = temp_dir.path().join("root_ca.crt");

    fs::write(
        &config,
        b"\
                [req]\n\
                distinguished_name=dn\n\
                [dn]\n\
                CN=localhost\n\
                [ext]\n\
                basicConstraints=CA:FALSE,pathlen:0\n\
                subjectAltName = @alt_names\n\
                extendedKeyUsage=serverAuth,clientAuth\n\
                [alt_names]\n\
                DNS.1 = localhost\n\
            ",
    )
    .unwrap();

    let subj = "/C=US/ST=Denial/L=Sprintfield/O=Dis/CN=localhost";
    // Making root CA
    let gen_ca = Command::new("openssl")
        .arg("req")
        .arg("-nodes")
        .arg("-x509")
        .arg("-newkey")
        .arg("rsa:2048")
        .arg("-config")
        .arg(&config)
        .arg("-extensions")
        .arg("ext")
        .arg("-subj")
        .arg(subj)
        .arg("-keyout")
        .arg(&keyfile)
        .arg("-out")
        .arg(&certfile)
        .arg("-days")
        .arg("1")
        .output()
        .unwrap();
    assert!(gen_ca.status.success());

    let cert = Pem::parse(&fs::read_to_string(&certfile).unwrap());
    let key = Pem::parse(&fs::read_to_string(&keyfile).unwrap());
    CertAndKeyPem { cert, key }
}

fn gen_cert_for_domain(domain: &str, ca: &CertAndKeyPem) -> CertAndKeyPem {
    assert!(!domain.is_empty());

    let temp_dir = tempdir::TempDir::new("pem-to-der").unwrap();
    let privkey_pem_path = temp_dir.path().join("privkey.pem");
    let csr = temp_dir.path().join("csr.pem");
    let ca_path = temp_dir.path().join("ca.pem");
    let ca_key_path = temp_dir.path().join("ca-key.pem");
    let cert_path = temp_dir.path().join("cert.pem");

    fs::write(&ca_path, &ca.cert.concat()).unwrap();
    fs::write(&ca_key_path, &ca.key.concat()).unwrap();

    assert!(Command::new("openssl")
        .arg("genrsa")
        .arg("-out")
        .arg(&privkey_pem_path)
        .arg("2048")
        .output()
        .unwrap()
        .status
        .success());

    // CSR
    assert!(Command::new("openssl")
        .arg("req")
        .arg("-new")
        .arg("-key")
        .arg(&privkey_pem_path)
        .arg("-out")
        .arg(&csr)
        .arg("-subj")
        .arg(format!(
            "/C=US/ST=Utah/L=Provo/O=ACME Service/CN={}",
            domain
        ))
        .output()
        .unwrap()
        .status
        .success());

    // Sign
    assert!(Command::new("openssl")
        .arg("x509")
        .arg("-req")
        .arg("-in")
        .arg(&csr)
        .arg("-CA")
        .arg(&ca_path)
        .arg("-CAkey")
        .arg(&ca_key_path)
        .arg("-CAcreateserial")
        .arg("-out")
        .arg(&cert_path)
        .arg("-days")
        .arg("1")
        .output()
        .unwrap()
        .status
        .success());

    let key = Pem::parse(&fs::read_to_string(&privkey_pem_path).unwrap());
    let cert = Pem::parse(&fs::read_to_string(&cert_path).unwrap());
    CertAndKeyPem { cert, key }
}

fn pem_to_der(cert: &Pem) -> X509Cert {
    let temp_dir = tempdir::TempDir::new("pem-to-der").unwrap();
    let certfile = temp_dir.path().join("cert.pem");
    fs::write(&certfile, &cert.concat()).unwrap();
    let cert_der = Command::new("openssl")
        .arg("x509")
        .arg("-outform")
        .arg("der")
        .arg("-in")
        .arg(&certfile)
        .output()
        .unwrap();
    assert!(cert_der.status.success());
    X509Cert::new(cert_der.stdout)
}

pub fn gen_keys() -> Keys {
    let root_ca_pem = gen_root_ca();

    let cert_der = pem_to_der(&root_ca_pem.cert);

    let root_ca_pkcs12 = pem_to_pkcs12(&root_ca_pem, "foobar");

    let server_cert_pem = gen_cert_for_domain("localhost", &root_ca_pem);

    Keys {
        client: ClientKeys { cert_der },
        server: ServerKeys {
            root_ca_pem,
            root_ca_pkcs12: Pkcs12AndPassword {
                pkcs12: root_ca_pkcs12,
                password: "foobar".to_owned(),
            },
            server_cert_pem,
        },
    }
}

/// Generate keys
pub fn keys() -> &'static Keys {
    static INIT: Once = Once::new();
    static mut KEYS: *mut Keys = ptr::null_mut();

    INIT.call_once(|| unsafe {
        KEYS = Box::into_raw(Box::new(gen_keys()));
    });
    unsafe { &*KEYS }
}

fn _pkcs12_to_pem(pkcs12: &Pkcs12, passin: &str) -> Pem {
    let mut command = Command::new("openssl")
        .arg("pkcs12")
        .arg("-passin")
        .arg(&format!("pass:{}", passin))
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

    Pem::parse(&pem)
}

fn pem_to_pkcs12(cert: &CertAndKeyPem, pass: &str) -> Pkcs12 {
    let temp_dir = tempdir::TempDir::new("pem-to-pkcs12").unwrap();

    let certfile = temp_dir.path().join("cert.pem");
    let keyfile = temp_dir.path().join("key.pem");

    fs::write(&certfile, &cert.cert.concat()).unwrap();
    fs::write(&keyfile, &cert.key.concat()).unwrap();

    let pkcs12out = Command::new("openssl")
        .arg("pkcs12")
        .arg("-export")
        .arg("-nodes")
        .arg("-inkey")
        .arg(&keyfile)
        .arg("-in")
        .arg(&certfile)
        .arg("-password")
        .arg(format!("pass:{}", pass))
        .output()
        .unwrap();
    assert!(pkcs12out.status.success());
    Pkcs12(pkcs12out.stdout)
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

    #[test]
    fn test() {
        // just check it does something
        super::keys();
    }

    #[test]
    fn verify() {
        let temp_dir = tempdir::TempDir::new("t").unwrap();

        let keys = gen_keys();

        let client = temp_dir.path().join("client");
        let server = temp_dir.path().join("server");

        fs::write(&client, keys.client.cert_der.as_bytes()).unwrap();
        fs::write(
            &server,
            keys.server.root_ca_pem.concat().concat().as_bytes(),
        )
        .unwrap();

        // error is, what does it mean?
        // ```
        // error 18 at 0 depth lookup:self signed certificate
        // ```
        let status = Command::new("openssl")
            .arg("verify")
            .arg("-CApath")
            .arg(&client)
            .arg(&server)
            .spawn()
            .unwrap()
            .wait()
            .unwrap();
        assert!(status.success())
    }

    #[test]
    fn client_server() {
        let temp_dir = tempdir::TempDir::new("client_server").unwrap();

        let keys = gen_keys();

        let client = temp_dir.path().join("client");
        let server = temp_dir.path().join("server.pem");

        fs::write(&client, keys.client.cert_der.as_bytes()).unwrap();
        fs::write(&server, keys.server.root_ca_pem.concat().concat()).unwrap();

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

        let lines = BufReader::new(s_server.stdout.as_mut().unwrap()).lines();
        for line in lines {
            let line = line.unwrap();
            if line == "ping" {
                break;
            }
            println!("> {}", line);
        }

        s_server.kill().unwrap();
        s_client.kill().unwrap();
    }
}
