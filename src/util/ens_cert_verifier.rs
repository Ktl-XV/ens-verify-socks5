use rustls::{
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer, ServerName, UnixTime as pkiUnixTime},
    CertificateError, DigitallySignedStruct, Error, SignatureScheme,
};
use x509_certificate::certificate::X509Certificate;

#[derive(Debug)]
pub struct EnsCertVerifier {}

impl ServerCertVerifier for EnsCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        server_name: &ServerName,
        _ocsp_response: &[u8],
        now: pkiUnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let cert = X509Certificate::from_der(end_entity).unwrap();

        if server_name.to_str() != cert.subject_common_name().unwrap() {
            return Err(Error::InvalidCertificate(CertificateError::NotValidForName));
        }

        if now.as_secs() < cert.validity_not_before().timestamp() as u64 {
            return Err(Error::InvalidCertificate(CertificateError::NotValidYet));
        }

        if now.as_secs() > cert.validity_not_after().timestamp() as u64 {
            return Err(Error::InvalidCertificate(CertificateError::Expired));
        }

        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA1,
            SignatureScheme::ECDSA_SHA1_Legacy,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
            SignatureScheme::ED448,
        ]
    }
}
