//! The one thing this crate needs a card for.
//!
//! Everything myna-sign produces — an OpenPGP signature, a CMS `SignedData`, an RFC 3161 request —
//! ends at the same operation: hand over a SHA-256 digest, get back a PKCS #1 v1.5 signature.
//! [`DigestSigner`] is that operation and nothing else.
//!
//! Keeping it this narrow is what makes the rest testable. The card's signing command cannot be
//! exercised without hardware, so it is confined to one method; [`SoftSigner`] implements the same
//! method with a software key, and every layer above is written against the trait.
//!
//! # Why a digest and not a message
//!
//! The card offers six signing schemes, three of which hash the message itself. None of those can
//! be used here. OpenPGP and CMS both sign a digest over bytes *this crate* assembles — an OpenPGP
//! trailer, or the DER of a set of signed attributes — not over the file the user picked, so a
//! card that hashes what it is given would hash the wrong thing. They also cap the input at what a
//! short APDU carries, which no real document fits in. `PreHashedDigestInfo` is the scheme that
//! takes a digest, and so it is the only one this crate uses.

use myna_card::Certificate;

use crate::error::{Error, Result};

/// Something that can sign a SHA-256 digest with the 署名用秘密鍵, or a stand-in for it.
///
/// Implementations return a 256 byte RSA-2048 signature that verifies as a standard
/// `sha256WithRSAEncryption` — that is, PKCS #1 v1.5 padding over a DigestInfo wrapping the
/// digest, not over the bare digest.
pub trait DigestSigner {
    /// The certificate belonging to the signing key.
    fn certificate(&self) -> &Certificate;

    /// Sign a SHA-256 digest.
    ///
    /// # Errors
    ///
    /// Whatever the card or key reports. Implementations do not check the result; use
    /// [`DigestSigner::sign_sha256_checked`] for that.
    fn sign_sha256(&mut self, digest: &[u8; 32]) -> Result<Vec<u8>>;

    /// Sign, then check the signature against the certificate's public key.
    ///
    /// One RSA public operation, against a signature that is about to be written into a file and
    /// handed to someone else. A wrong scheme, a corrupted exchange or a certificate that does not
    /// belong to the key is caught here rather than by whoever receives the result.
    ///
    /// # Errors
    ///
    /// [`Error::BadSignatureLength`] if the signature is not 256 bytes, and
    /// [`Error::SignatureInvalid`] if it does not verify.
    fn sign_sha256_checked(&mut self, digest: &[u8; 32]) -> Result<Vec<u8>> {
        use myna_card::ap::jpki::SignatureScheme;

        let signature = self.sign_sha256(digest)?;
        if signature.len() != 256 {
            return Err(Error::BadSignatureLength(signature.len()));
        }
        let key = self.certificate().public_key()?;
        SignatureScheme::PreHashedDigestInfo
            .verify(&key, digest, &signature)
            .map_err(|_| {
                Error::SignatureInvalid(
                    "the signature just produced does not verify against the signer's certificate"
                        .into(),
                )
            })?;
        Ok(signature)
    }
}

impl<T: DigestSigner + ?Sized> DigestSigner for &mut T {
    fn certificate(&self) -> &Certificate {
        (**self).certificate()
    }
    fn sign_sha256(&mut self, digest: &[u8; 32]) -> Result<Vec<u8>> {
        (**self).sign_sha256(digest)
    }
}

/// SHA-256 of `data`.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    use sha2::Digest as _;
    sha2::Sha256::digest(data).into()
}

// ---------------------------------------------------------------------------------------------

/// A software RSA key standing in for a card.
///
/// This is not a fallback for users without a card — it signs with a key that is in memory, which
/// is the thing the card exists to avoid. It is here so that the OpenPGP, CMS, PDF and RFC 3161
/// code can be built and tested without hardware, and so that the CLI can produce fixtures for
/// cross-checking against `gpg`, `pdfsig` and `openssl ts`.
#[cfg(feature = "soft-signer")]
pub struct SoftSigner {
    key: rsa::RsaPrivateKey,
    certificate: Certificate,
}

#[cfg(feature = "soft-signer")]
impl SoftSigner {
    /// Generate a 2048 bit key and a self-signed certificate for it.
    ///
    /// `subject` is an RFC 4514 distinguished name, for instance `CN=Test Signer,C=JP`. The
    /// validity runs from `not_before` for `days`; both are given rather than taken from the clock
    /// so that a fixture is the same every time it is built.
    pub fn generate(subject: &str, not_before: crate::time::Timestamp, days: u32) -> Result<Self> {
        use rand::rngs::OsRng;

        let key = rsa::RsaPrivateKey::new(&mut OsRng, 2048)
            .map_err(|e| Error::malformed(format!("generating an RSA key failed: {e}")))?;
        Self::from_key(key, subject, not_before, days)
    }

    /// Build a self-signed certificate for a key you already have.
    pub fn from_key(
        key: rsa::RsaPrivateKey,
        subject: &str,
        not_before: crate::time::Timestamp,
        days: u32,
    ) -> Result<Self> {
        use der::Encode as _;
        use rsa::pkcs1v15::SigningKey;
        use sha2::Sha256;
        use std::str::FromStr as _;
        use x509_cert::builder::{Builder, CertificateBuilder, Profile};
        use x509_cert::name::Name;
        use x509_cert::serial_number::SerialNumber;
        use x509_cert::spki::SubjectPublicKeyInfoOwned;
        use x509_cert::time::{Time, Validity};

        let signing_key = SigningKey::<Sha256>::new(key.clone());
        let name = Name::from_str(subject).map_err(|e| {
            Error::malformed(format!("{subject:?} is not a distinguished name: {e}"))
        })?;

        let not_after = crate::time::Timestamp::from_unix_seconds(
            not_before.unix_seconds() + i64::from(days) * 86_400,
        );
        let validity = Validity {
            not_before: Time::try_from(not_before.to_system_time()?)
                .map_err(|e| Error::der("notBefore", e))?,
            not_after: Time::try_from(not_after.to_system_time()?)
                .map_err(|e| Error::der("notAfter", e))?,
        };

        let spki = SubjectPublicKeyInfoOwned::from_key(key.to_public_key())
            .map_err(|e| Error::der("subjectPublicKeyInfo", e))?;

        // A leaf, not a root: the certificate on a card is an end entity certificate with
        // digitalSignature key usage, and anything downstream that looks at basic constraints
        // should see the same shape here.
        let profile = Profile::Leaf {
            issuer: name.clone(),
            enable_key_agreement: false,
            enable_key_encipherment: false,
        };

        let builder = CertificateBuilder::new(
            profile,
            SerialNumber::from(1u32),
            validity,
            name,
            spki,
            &signing_key,
        )
        .map_err(|e| Error::der("building a certificate", e))?;

        let cert = builder
            .build::<rsa::pkcs1v15::Signature>()
            .map_err(|e| Error::der("signing the certificate", e))?;
        let der = cert
            .to_der()
            .map_err(|e| Error::der("encoding the certificate", e))?;

        Ok(SoftSigner {
            key,
            certificate: Certificate::parse(&der)?,
        })
    }

    /// The private key, for tests that need to do something this trait does not expose.
    pub fn key(&self) -> &rsa::RsaPrivateKey {
        &self.key
    }
}

#[cfg(feature = "soft-signer")]
impl DigestSigner for SoftSigner {
    fn certificate(&self) -> &Certificate {
        &self.certificate
    }

    fn sign_sha256(&mut self, digest: &[u8; 32]) -> Result<Vec<u8>> {
        // `new_unprefixed` over a DigestInfo we build ourselves, rather than `new::<Sha256>()`
        // over a message: the input here is already hashed, which is exactly the position the
        // card is in.
        let digest_info = myna_card::data::sha256_digest_info(digest);
        self.key
            .sign(rsa::Pkcs1v15Sign::new_unprefixed(), &digest_info)
            .map_err(|e| Error::malformed(format!("signing failed: {e}")))
    }
}

#[cfg(all(test, feature = "soft-signer"))]
mod tests {
    use super::*;
    use crate::time::Timestamp;

    fn signer() -> SoftSigner {
        SoftSigner::generate(
            "CN=Test Signer,C=JP",
            Timestamp::from_unix_seconds(1_700_000_000),
            365,
        )
        .unwrap()
    }

    #[test]
    fn signs_and_checks_against_its_own_certificate() {
        let mut s = signer();
        let digest = sha256(b"hello");
        let signature = s.sign_sha256_checked(&digest).unwrap();
        assert_eq!(signature.len(), 256);
    }

    #[test]
    fn the_certificate_carries_the_signing_key() {
        let s = signer();
        use rsa::traits::PublicKeyParts as _;
        let from_cert = s.certificate().public_key().unwrap();
        assert_eq!(from_cert.modulus, s.key().to_public_key().n().to_bytes_be());
        assert_eq!(from_cert.bits(), 2048);
    }

    #[test]
    fn the_validity_is_the_one_asked_for_and_not_the_clock() {
        // A fixture built twice must be the same, so the dates cannot come from `SystemTime::now`.
        let s = signer();
        let (from, to) = s.certificate().validity();
        assert_eq!((from.year, from.month, from.day), (2023, 11, 14));
        assert_eq!((to.year, to.month, to.day), (2024, 11, 13));
    }

    #[test]
    fn a_signature_over_a_different_digest_does_not_verify() {
        let mut s = signer();
        let signature = s.sign_sha256(&sha256(b"hello")).unwrap();
        let key = s.certificate().public_key().unwrap();
        use myna_card::ap::jpki::SignatureScheme;
        assert!(
            SignatureScheme::PreHashedDigestInfo
                .verify(&key, &sha256(b"goodbye"), &signature)
                .is_err()
        );
    }
}
