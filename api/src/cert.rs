pub enum CertificateFormat {
    DER,
    PEM,
}

// X.509 certificate
pub struct Certificate {
    pub bytes: Vec<u8>,
    pub format: CertificateFormat,
}

impl Certificate {
    pub fn from_der(der: Vec<u8>) -> Certificate {
        Certificate {
            bytes: der,
            format: CertificateFormat::DER,
        }
    }

    pub fn into_der(self) -> Option<Vec<u8>> {
        // TODO: there are methods to convert PEM->DER which might be used here
        match self.format {
            CertificateFormat::DER => Some(self.bytes),
            _ => None,
        }
    }
    pub fn into_pem(self) -> Option<Vec<u8>> {
        // TODO: there are methods to convert DER->PEM which might be used here
        match self.format {
            CertificateFormat::PEM => Some(self.bytes),
            _ => None,
        }
    }
}
