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
    // TODO: result
    pub fn new(cert_der: impl Into<Vec<u8>>) -> X509Cert {
        let cert_der = cert_der.into();
        // Validate
        webpki::EndEntityCert::from(&cert_der).unwrap();
        X509Cert(cert_der)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

// X.509 certificate
#[derive(Debug, PartialEq, Clone)]
pub enum Cert {
    Pem(Pem),
    Der(X509Cert),
}

impl Cert {
    pub fn into_der(self) -> Option<X509Cert> {
        // TODO: there are methods to convert PEM->DER which might be used here
        match self {
            Cert::Der(d) => Some(d),
            _ => None,
        }
    }
    pub fn into_pem(self) -> Option<Pem> {
        // TODO: there are methods to convert DER->PEM which might be used here
        match self {
            Cert::Pem(p) => Some(p),
            _ => None,
        }
    }
}

/// DER-encoded
pub struct Pkcs12(pub Vec<u8>);

/// Pair of PKCS #12 and password.
pub struct Pkcs12AndPassword {
    pub pkcs12: Pkcs12,
    pub password: String,
}
