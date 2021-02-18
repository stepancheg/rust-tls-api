use std::ops::Add;

#[derive(Debug, PartialEq)]
pub struct Pem(pub Vec<pem::Pem>);

impl Add for &'_ Pem {
    type Output = Pem;

    fn add(self, rhs: &Pem) -> Pem {
        let mut r = self.clone();
        r.0.extend(rhs.clone().0);
        r
    }
}

// TODO: https://github.com/jcreekmore/pem-rs/pull/26
impl Clone for Pem {
    fn clone(&self) -> Self {
        Pem(self
            .0
            .iter()
            .map(|p| pem::Pem {
                tag: p.tag.clone(),
                contents: p.contents.clone(),
            })
            .collect())
    }
}

impl Pem {
    pub fn parse(input: &str) -> Pem {
        Pem(pem::parse_many(input))
    }

    pub fn concat(&self) -> String {
        let mut r = String::new();
        for p in &self.0 {
            r.push_str(&pem::encode(p));
        }
        r
    }
}

/// DER-encoded X.509 certificate.
#[derive(Debug, Eq, PartialEq, Clone)]
pub struct X509Cert(Vec<u8>);

impl X509Cert {
    fn looks_like_der(bytes: &[u8]) -> bool {
        // Quick check for certificate validity:
        // https://tools.ietf.org/html/rfc2459#section-4.1
        // ```
        //  Certificate  ::=  SEQUENCE  {
        //       tbsCertificate       TBSCertificate,
        //       signatureAlgorithm   AlgorithmIdentifier,
        //       signatureValue       BIT STRING  }
        // ```
        // and `SEQUENCE` tag is 0x30
        bytes.starts_with(b"\x30")
    }

    // TODO: result
    pub fn from_der(cert_der: impl Into<Vec<u8>>) -> crate::Result<X509Cert> {
        let cert_der = cert_der.into();
        if !Self::looks_like_der(&cert_der) {
            return Err(crate::Error::new_other("not a DER-encoded certificate"));
        }
        Ok(X509Cert(cert_der))
    }

    pub fn from_pem(cert_der_pem: impl AsRef<[u8]>) -> crate::Result<X509Cert> {
        let pem = pem::parse_many(cert_der_pem.as_ref());
        let count = pem.len();
        let mut certs: Vec<X509Cert> = pem
            .into_iter()
            .flat_map(|p| match p.tag == "CERTIFICATE" {
                true => Some(Self::from_der(p.contents)),
                false => None,
            })
            .collect::<Result<_, _>>()?;
        if certs.len() == 1 {
            return Ok(certs.swap_remove(0));
        } else if certs.len() > 1 {
            return Err(crate::Error::new_other("PEM file contains {} certificates"));
        } else if count != 0 {
            return Err(crate::Error::new_other(
                "PEM file contains {} entries, but no certificates",
            ));
        } else if Self::looks_like_der(cert_der_pem.as_ref()) {
            return Err(crate::Error::new_other("PEM file looks like a DER file"));
        } else {
            return Err(crate::Error::new_other(
                "no certificates found in a PEM file",
            ));
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn to_pem(&self) -> String {
        pem::encode(&pem::Pem {
            tag: "CERTIFICATE".to_owned(),
            contents: self.0.clone(),
        })
    }
}

/// DER-encoded
pub struct Pkcs12(pub Vec<u8>);

/// Pair of PKCS #12 and password.
pub struct Pkcs12AndPassword {
    pub pkcs12: Pkcs12,
    pub password: String,
}
