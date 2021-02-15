#[derive(Debug, PartialEq)]
pub struct Pem(pub Vec<pem::Pem>);

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

#[derive(Debug, Eq, PartialEq, Clone)]
pub struct Der(pub Vec<u8>);

// X.509 certificate
#[derive(Debug, PartialEq, Clone)]
pub enum Cert {
    Pem(Pem),
    Der(Der),
}

impl Cert {
    pub fn into_der(self) -> Option<Der> {
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
