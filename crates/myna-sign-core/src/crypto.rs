//! Checking a signature, whatever algorithm it turned out to use.
//!
//! # Why this is not just RSA
//!
//! Everything this program *produces* is RSA-2048 with SHA-256, because that is what the card
//! does. Everything it *verifies* is not. A real FreeTSA token, fetched while writing this, is
//! ECDSA on P-384 with SHA-512, under a responder certificate whose issuer signs with
//! `sha512WithRSAEncryption`; a real DigiCert token mixes SHA-256 and SHA-384 along one chain.
//! Assuming the verifier only ever meets the algorithms the signer emits is how a verifier ends up
//! rejecting valid signatures.
//!
//! # Unsupported is not invalid
//!
//! An algorithm this module does not implement comes back as [`Error::NotChecked`], never as a
//! failed signature. The two mean opposite things to a user — "we could not look" against "we
//! looked and it is forged" — and collapsing them would be the more dangerous direction.

use der::asn1::ObjectIdentifier;
use der::{Decode, Encode};

use crate::error::{Error, Result};

/// `id-ecPublicKey`.
const ID_EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
/// `rsaEncryption`.
const ID_RSA_ENCRYPTION: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");

const SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");
const SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.2");
const SHA512: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.3");

const SHA256_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
const SHA384_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.12");
const SHA512_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.13");

const ECDSA_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
const ECDSA_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3");
const ECDSA_SHA512: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.4");

const P256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
const P384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.34");
const P521: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.35");

/// A digest algorithm this program can compute.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Digest {
    /// SHA-256 — what the card signs, and what this program emits.
    Sha256,
    /// SHA-384.
    Sha384,
    /// SHA-512 — what FreeTSA's tokens use.
    Sha512,
}

impl Digest {
    /// From a digest algorithm identifier.
    pub fn from_oid(oid: ObjectIdentifier) -> Result<Self> {
        match oid {
            SHA256 => Ok(Digest::Sha256),
            SHA384 => Ok(Digest::Sha384),
            SHA512 => Ok(Digest::Sha512),
            other => Err(Error::NotChecked(format!(
                "digest algorithm {other} is not one this program computes"
            ))),
        }
    }

    /// The digest a signature algorithm identifier implies, if it names one.
    ///
    /// `rsaEncryption` on its own does not: in CMS the digest then comes from
    /// `SignerInfo.digestAlgorithm`, which is why this returns `None` rather than failing.
    pub fn from_signature_oid(oid: ObjectIdentifier) -> Option<Self> {
        match oid {
            SHA256_RSA | ECDSA_SHA256 => Some(Digest::Sha256),
            SHA384_RSA | ECDSA_SHA384 => Some(Digest::Sha384),
            SHA512_RSA | ECDSA_SHA512 => Some(Digest::Sha512),
            _ => None,
        }
    }

    /// Hash a message.
    pub fn hash(self, message: &[u8]) -> Vec<u8> {
        use sha2::Digest as _;
        match self {
            Digest::Sha256 => sha2::Sha256::digest(message).to_vec(),
            Digest::Sha384 => sha2::Sha384::digest(message).to_vec(),
            Digest::Sha512 => sha2::Sha512::digest(message).to_vec(),
        }
    }

    fn pkcs1v15(self) -> rsa::Pkcs1v15Sign {
        match self {
            Digest::Sha256 => rsa::Pkcs1v15Sign::new::<sha2::Sha256>(),
            Digest::Sha384 => rsa::Pkcs1v15Sign::new::<sha2::Sha384>(),
            Digest::Sha512 => rsa::Pkcs1v15Sign::new::<sha2::Sha512>(),
        }
    }
}

/// Check `signature` over `message`, with the public key in `spki_der`.
///
/// `signature_algorithm` names the algorithm; when it does not also name a digest — plain
/// `rsaEncryption`, as CMS writes it — `fallback_digest` is used, which is where
/// `SignerInfo.digestAlgorithm` goes.
pub fn verify(
    spki_der: &[u8],
    signature_algorithm: ObjectIdentifier,
    fallback_digest: Option<Digest>,
    message: &[u8],
    signature: &[u8],
) -> Result<()> {
    let spki = spki::SubjectPublicKeyInfoOwned::from_der(spki_der)
        .map_err(|e| Error::der("subjectPublicKeyInfo", e))?;
    let key_bits = spki
        .subject_public_key
        .as_bytes()
        .ok_or_else(|| Error::malformed("the public key is not a whole number of bytes"))?;

    let digest = Digest::from_signature_oid(signature_algorithm)
        .or(fallback_digest)
        .ok_or_else(|| {
            Error::NotChecked(format!(
                "signature algorithm {signature_algorithm} names no digest and none was supplied"
            ))
        })?;

    match spki.algorithm.oid {
        ID_RSA_ENCRYPTION => verify_rsa(key_bits, digest, message, signature),
        ID_EC_PUBLIC_KEY => {
            let curve = spki
                .algorithm
                .parameters
                .as_ref()
                .and_then(|p| p.decode_as::<ObjectIdentifier>().ok())
                .ok_or_else(|| Error::NotChecked("the EC key names no curve".into()))?;
            verify_ecdsa(curve, key_bits, digest, message, signature)
        }
        other => Err(Error::NotChecked(format!(
            "public key algorithm {other} is not one this program checks"
        ))),
    }
}

fn verify_rsa(key_bits: &[u8], digest: Digest, message: &[u8], signature: &[u8]) -> Result<()> {
    use rsa::pkcs1::DecodeRsaPublicKey as _;
    let key = rsa::RsaPublicKey::from_pkcs1_der(key_bits)
        .map_err(|_| Error::malformed("the key is labelled RSA but does not decode as one"))?;
    key.verify(digest.pkcs1v15(), &digest.hash(message), signature)
        .map_err(|_| Error::SignatureInvalid("the RSA signature does not verify".into()))
}

/// ECDSA over one of the three NIST prime curves.
///
/// The digest is not the curve's "natural" one: FreeTSA signs a P-384 key with SHA-512, which is
/// legal and which a verifier hard-coded to SHA-384 would reject. Hashing here and verifying the
/// prehash is what keeps the two independent — ECDSA truncates the digest to the field size, which
/// is the specified behaviour when they differ.
fn verify_ecdsa(
    curve: ObjectIdentifier,
    key_bits: &[u8],
    digest: Digest,
    message: &[u8],
    signature: &[u8],
) -> Result<()> {
    use signature::hazmat::PrehashVerifier;

    let hash = digest.hash(message);
    let bad = || Error::SignatureInvalid("the ECDSA signature does not verify".into());

    match curve {
        P256 => {
            let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(key_bits)
                .map_err(|_| Error::malformed("not a P-256 point"))?;
            let sig = p256::ecdsa::Signature::from_der(signature)
                .map_err(|_| Error::malformed("not a DER ECDSA signature"))?;
            key.verify_prehash(&hash, &sig).map_err(|_| bad())
        }
        P384 => {
            let key = p384::ecdsa::VerifyingKey::from_sec1_bytes(key_bits)
                .map_err(|_| Error::malformed("not a P-384 point"))?;
            let sig = p384::ecdsa::Signature::from_der(signature)
                .map_err(|_| Error::malformed("not a DER ECDSA signature"))?;
            key.verify_prehash(&hash, &sig).map_err(|_| bad())
        }
        P521 => {
            let key = p521::ecdsa::VerifyingKey::from_sec1_bytes(key_bits)
                .map_err(|_| Error::malformed("not a P-521 point"))?;
            let sig = p521::ecdsa::Signature::from_der(signature)
                .map_err(|_| Error::malformed("not a DER ECDSA signature"))?;
            key.verify_prehash(&hash, &sig).map_err(|_| bad())
        }
        other => Err(Error::NotChecked(format!(
            "elliptic curve {other} is not one this program checks"
        ))),
    }
}

/// The `SubjectPublicKeyInfo` of a certificate, DER.
pub fn spki_of(certificate_der: &[u8]) -> Result<Vec<u8>> {
    x509_cert::Certificate::from_der(certificate_der)
        .map_err(|e| Error::der("certificate", e))?
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(|e| Error::der("subjectPublicKeyInfo", e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_the_digests_both_ways() {
        assert_eq!(Digest::from_oid(SHA512).unwrap(), Digest::Sha512);
        assert_eq!(
            Digest::from_signature_oid(ECDSA_SHA512),
            Some(Digest::Sha512)
        );
        assert_eq!(Digest::from_signature_oid(SHA384_RSA), Some(Digest::Sha384));
        // rsaEncryption names no digest; CMS supplies it separately.
        assert_eq!(Digest::from_signature_oid(ID_RSA_ENCRYPTION), None);
    }

    #[test]
    fn an_algorithm_we_do_not_implement_is_not_checked_rather_than_invalid() {
        // Ed25519 — a perfectly good signature this program cannot check.
        let ed25519 = ObjectIdentifier::new_unwrap("1.3.101.112");
        let e = Digest::from_oid(ed25519).unwrap_err();
        assert!(matches!(e, Error::NotChecked(_)), "{e:?}");
    }

    #[test]
    fn hashes_have_the_lengths_they_should() {
        assert_eq!(Digest::Sha256.hash(b"x").len(), 32);
        assert_eq!(Digest::Sha384.hash(b"x").len(), 48);
        assert_eq!(Digest::Sha512.hash(b"x").len(), 64);
    }
}
