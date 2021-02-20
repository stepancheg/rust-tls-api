use std::fs;
use std::process::Command;
use std::process::Stdio;

/// Convert DER certificate to PKCS #12 using openssl command.
pub(crate) fn der_to_pkcs12(cert: &[u8], key: &[u8]) -> crate::Result<(Vec<u8>, String)> {
    let temp_dir = tempdir::TempDir::new("tls-api-der-to-pkcs12").unwrap();

    let cert_file = temp_dir.path().join("cert.pem");
    let pkcs12_file = temp_dir.path().join("cert.pkcs12");

    let passphrase = "tls-api-123";

    let pem_data = pem::encode_many(&[
        pem::Pem {
            tag: "CERTIFICATE".to_owned(),
            contents: cert.to_owned(),
        },
        pem::Pem {
            // Technically it can be non-RSA PRIVATE KEY
            tag: "RSA PRIVATE KEY".to_owned(),
            contents: key.to_owned(),
        },
    ]);

    fs::write(&cert_file, pem_data)?;

    let output = Command::new("openssl")
        .arg("pkcs12")
        .arg("-export")
        .arg("-nodes")
        .arg("-in")
        .arg(&cert_file)
        .arg("-out")
        .arg(&pkcs12_file)
        .arg("-password")
        .arg(format!("pass:{}", passphrase))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .output()?;

    if !output.status.success() {
        return Err(crate::CommonError::OpensslCommandFailedToConvert.into());
    }

    let pkcs12 = fs::read(pkcs12_file)?;
    Ok((pkcs12, passphrase.to_owned()))
}

/// PKCS #12 certificate to DER using openssl command.
pub(crate) fn pkcs12_to_der(pkcs12: &[u8], passphrase: &str) -> crate::Result<(Vec<u8>, Vec<u8>)> {
    let temp_dir = tempdir::TempDir::new("tls-api-der-to-pkcs12").unwrap();

    let cert_pem_file = temp_dir.path().join("cert.pem");
    let pkcs12_file = temp_dir.path().join("cert.pkcs12");

    fs::write(&pkcs12_file, pkcs12)?;

    let output = Command::new("openssl")
        .arg("pkcs12")
        .arg("-nodes")
        .arg("-in")
        .arg(&pkcs12_file)
        .arg("-out")
        .arg(&cert_pem_file)
        .arg("-password")
        .arg(format!("pass:{}", passphrase))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .output()?;

    if !output.status.success() {
        return Err(crate::CommonError::OpensslCommandFailedToConvert.into());
    }

    let cert_pem = fs::read_to_string(cert_pem_file)?;
    let pems = pem::parse_many(cert_pem);
    let mut certificates: Vec<Vec<u8>> = pems
        .iter()
        .flat_map(|p| match p.tag.as_str() {
            "CERTIFICATE" => Some(p.contents.clone()),
            _ => None,
        })
        .collect();
    let mut keys: Vec<Vec<u8>> = pems
        .iter()
        .flat_map(|p| match p.tag.as_str() {
            "PRIVATE KEY" | "RSA PRIVATE KEY" => Some(p.contents.clone()),
            _ => None,
        })
        .collect();
    if keys.len() != 1 || certificates.len() != 1 {
        return Err(
            crate::CommonError::PemFromPkcs12ContainsNotSingleCertKeyPair(
                pems.iter().map(|p| p.tag.clone()).collect(),
            )
            .into(),
        );
    }
    Ok((certificates.swap_remove(0), keys.swap_remove(0)))
}
