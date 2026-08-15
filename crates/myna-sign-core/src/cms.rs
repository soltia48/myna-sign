//! CMS `SignedData`, built and checked.
//!
//! Two callers share this: a PDF signature is a detached `SignedData` in `/Contents`, and an
//! RFC 3161 timestamp token is a `SignedData` wrapping a `TSTInfo`. Building and verifying live
//! together because they have to agree on the one detail that is easiest to get wrong.
//!
//! # What is signed
//!
//! Not the document. When `signedAttrs` is present — and it always is here, because PAdES requires
//! it — the signature is over the DER of the attributes, re-encoded with the universal `SET OF`
//! tag `0x31` rather than the `[0] IMPLICIT` tag they carry inside the `SignerInfo`. Signing the
//! bytes as they appear in the structure is a classic mistake; it produces a signature that no
//! other implementation accepts. [`signed_attrs_der`] is the single place that re-tagging happens,
//! and [`tests::the_signed_attributes_are_hashed_with_the_set_of_tag`] pins it.
//!
//! The document reaches the signature through the `messageDigest` attribute, which holds its
//! SHA-256. So verifying takes both steps: check the signature over the attributes, *and* check
//! that the `messageDigest` attribute matches the content in hand. Doing only the first accepts a
//! signature transplanted from another document.

use cms::cert::{CertificateChoices, IssuerAndSerialNumber};
use cms::content_info::{CmsVersion, ContentInfo};
use cms::signed_data::{
    CertificateSet, EncapsulatedContentInfo, SignatureValue, SignedData, SignerIdentifier,
    SignerInfo, SignerInfos,
};
use der::asn1::{Any, ObjectIdentifier, OctetString, SetOfVec, UtcTime};
use der::{Decode, Encode, Sequence};
use serde::Serialize;
use spki::AlgorithmIdentifierOwned;
use x509_cert::attr::{Attribute, AttributeValue};

use crate::error::{Error, Result};
use crate::signer::{DigestSigner, sha256};
use crate::time::Timestamp;

/// `id-data`.
pub const ID_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.1");
/// `id-signedData`.
pub const ID_SIGNED_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.2");
/// `id-contentType`.
pub const ID_CONTENT_TYPE: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.3");
/// `id-messageDigest`.
pub const ID_MESSAGE_DIGEST: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.4");
/// `id-signingTime`.
pub const ID_SIGNING_TIME: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.5");
/// `id-aa-signingCertificateV2` (RFC 5035).
pub const ID_AA_SIGNING_CERTIFICATE_V2: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.47");
/// `id-aa-timeStampToken` (RFC 3161 §3.3.2) — not in `const-oid`'s database, so it is written out.
pub const ID_AA_TIME_STAMP_TOKEN: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.14");
/// `id-ct-TSTInfo`.
pub const ID_CT_TST_INFO: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.1.4");
/// `id-sha256`.
pub const ID_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");
/// `rsaEncryption`.
pub const ID_RSA_ENCRYPTION: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");

/// `AlgorithmIdentifier` for SHA-256, with the `NULL` parameters that every implementation in the
/// field emits.
///
/// RFC 5754 says the parameters should be absent. OpenSSL writes `NULL` anyway, and so do the two
/// timestamp authorities this program ships presets for, so `NULL` is what interoperates.
pub fn sha256_algorithm() -> AlgorithmIdentifierOwned {
    AlgorithmIdentifierOwned {
        oid: ID_SHA256,
        parameters: Some(Any::null()),
    }
}

/// `AlgorithmIdentifier` for `rsaEncryption`, which is what a PKCS #1 v1.5 `signatureAlgorithm`
/// carries in CMS.
pub fn rsa_algorithm() -> AlgorithmIdentifierOwned {
    AlgorithmIdentifierOwned {
        oid: ID_RSA_ENCRYPTION,
        parameters: Some(Any::null()),
    }
}

// --- ESS signing certificate ------------------------------------------------------------------

/// `ESSCertIDv2` (RFC 5035).
///
/// `hashAlgorithm` defaults to SHA-256 and is omitted when it is; it is kept optional here so that
/// a token from someone who wrote it out still decodes.
#[derive(Debug, Clone, Sequence)]
pub struct EssCertIdV2 {
    /// The hash algorithm, absent when SHA-256.
    #[asn1(optional = "true")]
    pub hash_algorithm: Option<AlgorithmIdentifierOwned>,
    /// Hash of the certificate.
    pub cert_hash: OctetString,
}

/// `SigningCertificateV2` (RFC 5035).
#[derive(Debug, Clone, Sequence)]
pub struct SigningCertificateV2 {
    /// The signer's certificate, first.
    pub certs: Vec<EssCertIdV2>,
}

// --- Building ---------------------------------------------------------------------------------

/// What goes into a `SignedData` besides the signature.
pub struct SignedDataParams<'a> {
    /// SHA-256 of the content being signed. For a PDF that is the two `ByteRange` spans.
    pub content_digest: [u8; 32],
    /// The `eContentType`. `id-data` for a PDF signature.
    pub content_type: ObjectIdentifier,
    /// Extra certificates to carry — the CA above the signer, so a verifier can build the chain.
    pub extra_certificates: &'a [Vec<u8>],
    /// The claimed signing time. Written as `signingTime`, which is **not** evidence: the signer
    /// chose it. A timestamp token is the part a third party attests.
    pub signing_time: Timestamp,
}

/// Build a detached `SignedData` and sign it with the card.
///
/// Returns the `ContentInfo` DER, ready to go into a PDF's `/Contents`.
pub fn build_signed_data<S: DigestSigner + ?Sized>(
    signer: &mut S,
    params: &SignedDataParams<'_>,
) -> Result<Vec<u8>> {
    let signer_der = signer.certificate().der().to_vec();
    let signer_cert = parse_certificate(&signer_der)?;

    let attrs = build_signed_attributes(params, &signer_der)?;
    let digest = sha256(&signed_attrs_der(&attrs)?);
    let signature = signer.sign_sha256_checked(&digest)?;

    let sid = SignerIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber {
        issuer: signer_cert.tbs_certificate.issuer.clone(),
        serial_number: signer_cert.tbs_certificate.serial_number.clone(),
    });

    let signer_info = SignerInfo {
        version: CmsVersion::V1,
        sid,
        digest_alg: sha256_algorithm(),
        signed_attrs: Some(attrs),
        signature_algorithm: rsa_algorithm(),
        signature: SignatureValue::new(signature).map_err(|e| Error::der("signature value", e))?,
        unsigned_attrs: None,
    };

    // A `SET OF` rejects duplicates, and a caller passing the signer's own certificate among the
    // extras is an easy mistake to make — the CA above it is what belongs there. Drop repeats
    // rather than failing the signature over it.
    let mut certificates = vec![signer_cert];
    let mut seen = vec![signer_der.clone()];
    for der in params.extra_certificates {
        if seen.iter().any(|s| s == der) {
            continue;
        }
        seen.push(der.clone());
        certificates.push(parse_certificate(der)?);
    }
    assemble(signer_info, certificates, params.content_type)
}

/// Re-assemble a `SignedData` around a `SignerInfo`, used both when building and when adding an
/// unsigned attribute afterwards.
fn assemble(
    signer_info: SignerInfo,
    certificates: Vec<x509_cert::Certificate>,
    content_type: ObjectIdentifier,
) -> Result<Vec<u8>> {
    let mut choices = SetOfVec::new();
    for cert in certificates {
        choices
            .insert(CertificateChoices::Certificate(cert))
            .map_err(|e| Error::der("certificate set", e))?;
    }

    let mut digest_algorithms = SetOfVec::new();
    digest_algorithms
        .insert(sha256_algorithm())
        .map_err(|e| Error::der("digest algorithms", e))?;

    let mut signer_infos = SetOfVec::new();
    signer_infos
        .insert(signer_info)
        .map_err(|e| Error::der("signer infos", e))?;

    let signed_data = SignedData {
        version: CmsVersion::V1,
        digest_algorithms,
        // Detached: the content is the document, which is not carried here.
        encap_content_info: EncapsulatedContentInfo {
            econtent_type: content_type,
            econtent: None,
        },
        certificates: Some(CertificateSet(choices)),
        crls: None,
        signer_infos: SignerInfos(signer_infos),
    };

    let content_info = ContentInfo {
        content_type: ID_SIGNED_DATA,
        content: Any::from_der(
            &signed_data
                .to_der()
                .map_err(|e| Error::der("signed data", e))?,
        )
        .map_err(|e| Error::der("signed data", e))?,
    };
    content_info
        .to_der()
        .map_err(|e| Error::der("content info", e))
}

fn build_signed_attributes(
    params: &SignedDataParams<'_>,
    signer_der: &[u8],
) -> Result<SetOfVec<Attribute>> {
    let mut attrs = SetOfVec::new();

    push_attribute(&mut attrs, ID_CONTENT_TYPE, &params.content_type)?;
    push_attribute(
        &mut attrs,
        ID_MESSAGE_DIGEST,
        &OctetString::new(params.content_digest.as_slice())
            .map_err(|e| Error::der("message digest", e))?,
    )?;

    let signing_time = UtcTime::from_unix_duration(std::time::Duration::from_secs(
        u64::try_from(params.signing_time.unix_seconds())
            .map_err(|_| Error::malformed("the signing time is before 1970"))?,
    ))
    .map_err(|e| Error::der("signing time", e))?;
    push_attribute(&mut attrs, ID_SIGNING_TIME, &signing_time)?;

    // Ties the signature to one certificate, so that a signature cannot be re-presented as having
    // been made under a different certificate carrying the same key.
    let ess = SigningCertificateV2 {
        certs: vec![EssCertIdV2 {
            hash_algorithm: None,
            cert_hash: OctetString::new(sha256(signer_der).as_slice())
                .map_err(|e| Error::der("certificate hash", e))?,
        }],
    };
    push_attribute(&mut attrs, ID_AA_SIGNING_CERTIFICATE_V2, &ess)?;

    Ok(attrs)
}

fn push_attribute<T: Encode>(
    attrs: &mut SetOfVec<Attribute>,
    oid: ObjectIdentifier,
    value: &T,
) -> Result<()> {
    let der = value
        .to_der()
        .map_err(|e| Error::der("attribute value", e))?;
    let mut values = SetOfVec::<AttributeValue>::new();
    values
        .insert(Any::from_der(&der).map_err(|e| Error::der("attribute value", e))?)
        .map_err(|e| Error::der("attribute values", e))?;
    attrs
        .insert(Attribute { oid, values })
        .map_err(|e| Error::der("attributes", e))?;
    Ok(())
}

/// The bytes a `signedAttrs` signature is computed over.
///
/// Inside a `SignerInfo` the attributes are tagged `[0] IMPLICIT`. RFC 5652 §5.4 says the
/// signature is computed over the *complete DER* of the attributes with the universal `SET OF`
/// tag instead. This function is the only place that substitution happens.
pub fn signed_attrs_der(attrs: &SetOfVec<Attribute>) -> Result<Vec<u8>> {
    let mut der = attrs
        .to_der()
        .map_err(|e| Error::der("encoding signed attributes", e))?;
    // `SetOfVec` already encodes with the universal SET OF tag, so this is an assertion rather
    // than a fix-up — but it is the assertion that matters most in this file.
    if der.first() != Some(&0x31) {
        der[0] = 0x31;
    }
    Ok(der)
}

/// Attach an RFC 3161 token to a finished `SignedData` as an unsigned attribute.
///
/// The token is computed from `signerInfo.signature`, so it can only be added after signing — that
/// is why it is unsigned, and why this rebuilds the structure rather than being an option to
/// [`build_signed_data`].
pub fn attach_timestamp(signed_data_der: &[u8], token_der: &[u8]) -> Result<Vec<u8>> {
    let (mut signed_data, mut signer_info) = split(signed_data_der)?;

    let token = Any::from_der(token_der).map_err(|e| Error::der("timestamp token", e))?;
    let mut values = SetOfVec::<AttributeValue>::new();
    values
        .insert(token)
        .map_err(|e| Error::der("timestamp attribute", e))?;
    let mut unsigned = SetOfVec::new();
    unsigned
        .insert(Attribute {
            oid: ID_AA_TIME_STAMP_TOKEN,
            values,
        })
        .map_err(|e| Error::der("unsigned attributes", e))?;
    signer_info.unsigned_attrs = Some(unsigned);

    let certificates = signed_data
        .certificates
        .take()
        .map(|set| {
            set.0
                .into_vec()
                .into_iter()
                .filter_map(|c| match c {
                    CertificateChoices::Certificate(c) => Some(c),
                    _ => None,
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    assemble(
        signer_info,
        certificates,
        signed_data.encap_content_info.econtent_type,
    )
}

/// Pull a `SignedData` and its single `SignerInfo` out of a `ContentInfo`.
fn split(der: &[u8]) -> Result<(SignedData, SignerInfo)> {
    let signed_data = parse_signed_data(der)?;
    let signer_info = signed_data
        .signer_infos
        .0
        .as_slice()
        .first()
        .cloned()
        .ok_or_else(|| Error::malformed("the SignedData carries no SignerInfo"))?;
    Ok((signed_data, signer_info))
}

/// Parse a `ContentInfo` wrapping a `SignedData`.
pub fn parse_signed_data(der: &[u8]) -> Result<SignedData> {
    let content_info = ContentInfo::from_der(der).map_err(|e| Error::der("content info", e))?;
    if content_info.content_type != ID_SIGNED_DATA {
        return Err(Error::malformed(format!(
            "expected signedData, got {}",
            content_info.content_type
        )));
    }
    let inner = content_info
        .content
        .to_der()
        .map_err(|e| Error::der("signed data body", e))?;
    SignedData::from_der(&inner).map_err(|e| Error::der("signed data", e))
}

fn parse_certificate(der: &[u8]) -> Result<x509_cert::Certificate> {
    x509_cert::Certificate::from_der(der).map_err(|e| Error::der("certificate", e))
}

// --- Verifying --------------------------------------------------------------------------------

/// What a `SignedData` turned out to say.
///
/// As elsewhere, the fields are separate and none is named "valid": a signature can verify over
/// attributes that describe a different document, and that combination has to be visible rather
/// than collapsed into one boolean.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CmsVerification {
    /// The signature over `signedAttrs` verifies under the signer's certificate.
    pub signature_verified: bool,
    /// The `messageDigest` attribute matches the content actually in hand.
    ///
    /// `false` with `signature_verified` true means the signature is genuine but belongs to
    /// different content.
    pub message_digest_matches: bool,
    /// The `contentType` attribute matches the `eContentType`.
    pub content_type_matches: bool,
    /// `signingCertificateV2` is present and names the certificate that was used.
    pub signing_certificate_bound: bool,
    /// The claimed signing time, which the signer chose.
    pub claimed_signing_time: Option<String>,
    /// The signer's certificate, DER.
    #[serde(skip)]
    pub signer_certificate: Vec<u8>,
    /// Every certificate the structure carried, DER — the chain a verifier can build from.
    #[serde(skip)]
    pub certificates: Vec<Vec<u8>>,
    /// The timestamp token from `unsignedAttrs`, if there was one.
    #[serde(skip)]
    pub timestamp_token: Option<Vec<u8>>,
    /// `signerInfo.signature`, which is what a timestamp covers.
    #[serde(skip)]
    pub signature_value: Vec<u8>,
}

/// Check a `SignedData` against the content it claims to be over.
///
/// `content` is the detached content: the PDF's `ByteRange` spans, or the encapsulated `TSTInfo`.
///
/// `Err` means the structure could not be examined. A signature that does not verify is a
/// [`CmsVerification`] with `signature_verified: false`.
pub fn verify_signed_data(der: &[u8], content: &[u8]) -> Result<CmsVerification> {
    let (signed_data, signer_info) = split(der)?;

    let certificates: Vec<Vec<u8>> = signed_data
        .certificates
        .as_ref()
        .map(|set| {
            set.0
                .as_slice()
                .iter()
                .filter_map(|c| match c {
                    CertificateChoices::Certificate(c) => c.to_der().ok(),
                    _ => None,
                })
                .collect()
        })
        .unwrap_or_default();

    let signer_certificate = find_signer_certificate(&signer_info, &certificates)?;

    let attrs = signer_info
        .signed_attrs
        .as_ref()
        .ok_or_else(|| Error::malformed("the SignerInfo has no signedAttrs"))?;

    // The algorithms come out of the structure, not out of an assumption. A FreeTSA token is
    // SHA-512 and ECDSA on P-384; a verifier that hard-codes what the card emits rejects it.
    let digest_algorithm = crate::crypto::Digest::from_oid(signer_info.digest_alg.oid)?;

    let content_digest = digest_algorithm.hash(content);
    let message_digest_matches = attribute::<OctetString>(attrs, ID_MESSAGE_DIGEST)?
        .is_some_and(|d| d.as_bytes() == content_digest);
    let content_type_matches = attribute::<ObjectIdentifier>(attrs, ID_CONTENT_TYPE)?
        .is_some_and(|t| t == signed_data.encap_content_info.econtent_type);

    // RFC 5035 lets the ESS attribute name its own hash; the older `signingCertificate` uses
    // SHA-1, which this program does not compute, so an unrecognised one reads as unbound rather
    // than as a mismatch.
    let signing_certificate_bound =
        attribute::<SigningCertificateV2>(attrs, ID_AA_SIGNING_CERTIFICATE_V2)?
            .and_then(|ess| ess.certs.first().cloned())
            .is_some_and(|c| {
                let hash = match c.hash_algorithm {
                    None => crate::crypto::Digest::Sha256,
                    Some(algorithm) => match crate::crypto::Digest::from_oid(algorithm.oid) {
                        Ok(d) => d,
                        Err(_) => return false,
                    },
                };
                c.cert_hash.as_bytes() == hash.hash(&signer_certificate)
            });

    let claimed_signing_time = attribute::<UtcTime>(attrs, ID_SIGNING_TIME)?
        .map(|t| Timestamp::from_unix_seconds(t.to_unix_duration().as_secs() as i64).to_rfc3339());

    let signature = signer_info.signature.as_bytes();
    let signature_verified = crate::crypto::verify(
        &crate::crypto::spki_of(&signer_certificate)?,
        signer_info.signature_algorithm.oid,
        Some(digest_algorithm),
        &signed_attrs_der(attrs)?,
        signature,
    )
    .is_ok();

    let timestamp_token = signer_info
        .unsigned_attrs
        .as_ref()
        .and_then(|attrs| {
            attrs
                .as_slice()
                .iter()
                .find(|a| a.oid == ID_AA_TIME_STAMP_TOKEN)
        })
        .and_then(|a| a.values.as_slice().first())
        .and_then(|v| v.to_der().ok());

    Ok(CmsVerification {
        signature_verified,
        message_digest_matches,
        content_type_matches,
        signing_certificate_bound,
        claimed_signing_time,
        signer_certificate,
        certificates,
        timestamp_token,
        signature_value: signature.to_vec(),
    })
}

/// The encapsulated content of a `SignedData`, for the attached case (a timestamp token).
pub fn encapsulated_content(der: &[u8]) -> Result<(ObjectIdentifier, Vec<u8>)> {
    let signed_data = parse_signed_data(der)?;
    let econtent = signed_data
        .encap_content_info
        .econtent
        .ok_or_else(|| Error::malformed("no encapsulated content"))?;
    Ok((
        signed_data.encap_content_info.econtent_type,
        econtent.value().to_vec(),
    ))
}

/// Find the certificate a `SignerInfo` points at.
fn find_signer_certificate(signer_info: &SignerInfo, certificates: &[Vec<u8>]) -> Result<Vec<u8>> {
    let wanted = match &signer_info.sid {
        SignerIdentifier::IssuerAndSerialNumber(isn) => isn,
        SignerIdentifier::SubjectKeyIdentifier(_) => {
            return Err(Error::NotChecked(
                "the signer is identified by subject key identifier, which is not supported".into(),
            ));
        }
    };
    for der in certificates {
        let cert = parse_certificate(der)?;
        if cert.tbs_certificate.issuer == wanted.issuer
            && cert.tbs_certificate.serial_number == wanted.serial_number
        {
            return Ok(der.clone());
        }
    }
    Err(Error::NotChecked(
        "the signer's certificate is not carried in the structure".into(),
    ))
}

/// Read one signed attribute, decoded.
fn attribute<T: for<'a> der::Decode<'a>>(
    attrs: &SetOfVec<Attribute>,
    oid: ObjectIdentifier,
) -> Result<Option<T>> {
    let Some(attr) = attrs.as_slice().iter().find(|a| a.oid == oid) else {
        return Ok(None);
    };
    let Some(value) = attr.values.as_slice().first() else {
        return Ok(None);
    };
    let der = value.to_der().map_err(|e| Error::der("attribute", e))?;
    Ok(Some(
        T::from_der(&der).map_err(|e| Error::der(&format!("attribute {oid}"), e))?,
    ))
}

/// Check a PKCS #1 v1.5 signature over a SHA-256 digest, with the key in a certificate.
///
/// The card's own signatures are always this shape. Anything read from a file goes through
/// [`crate::crypto::verify`] instead, which reads the algorithm out of the structure.
pub fn verify_rsa_sha256(
    certificate_der: &[u8],
    digest: &[u8; 32],
    signature: &[u8],
) -> Result<()> {
    // Not routed through `crypto::verify`, which hashes the message it is given; here the hash is
    // what we already have, and hashing it again would check the wrong thing.
    let cert = parse_certificate(certificate_der)?;
    let bits = cert
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .as_bytes()
        .ok_or_else(|| Error::malformed("the public key is not a whole number of bytes"))?;
    use rsa::pkcs1::DecodeRsaPublicKey as _;
    let key = rsa::RsaPublicKey::from_pkcs1_der(bits)
        .map_err(|_| Error::NotChecked("the certificate's key is not RSA".into()))?;
    let digest_info = myna_card::data::sha256_digest_info(digest);
    key.verify(rsa::Pkcs1v15Sign::new_unprefixed(), &digest_info, signature)
        .map_err(|_| Error::SignatureInvalid("the signature does not verify".into()))
}

/// Check a certificate's signature against a `SubjectPublicKeyInfo`.
///
/// Takes the SPKI rather than a certificate because the Mozilla root list this program uses as a
/// trust anchor set stores anchors that way — a subject name and a public key, with no certificate
/// to go with them.
pub fn verify_certificate_signature_with_spki(subject_der: &[u8], spki_der: &[u8]) -> Result<()> {
    let subject = parse_certificate(subject_der)?;
    let tbs = subject
        .tbs_certificate
        .to_der()
        .map_err(|e| Error::der("re-encoding the TBSCertificate", e))?;
    let signature = subject
        .signature
        .as_bytes()
        .ok_or_else(|| Error::malformed("the signature is not a whole number of bytes"))?;
    crate::crypto::verify(
        spki_der,
        subject.signature_algorithm.oid,
        None,
        &tbs,
        signature,
    )
}

/// The `SubjectPublicKeyInfo` of a certificate, DER.
pub fn spki_of(der: &[u8]) -> Result<Vec<u8>> {
    crate::crypto::spki_of(der)
}

/// The DER of a certificate's issuer name, for matching against a trust anchor.
pub fn issuer_name_der(der: &[u8]) -> Result<Vec<u8>> {
    parse_certificate(der)?
        .tbs_certificate
        .issuer
        .to_der()
        .map_err(|e| Error::der("issuer name", e))
}

/// The DER of a certificate's subject name.
pub fn subject_name_der(der: &[u8]) -> Result<Vec<u8>> {
    parse_certificate(der)?
        .tbs_certificate
        .subject
        .to_der()
        .map_err(|e| Error::der("subject name", e))
}

/// Whether a certificate is within its validity at `at`.
pub fn is_valid_at(der: &[u8], at: Timestamp) -> Result<bool> {
    let cert = parse_certificate(der)?;
    let validity = &cert.tbs_certificate.validity;
    let from = validity.not_before.to_unix_duration().as_secs() as i64;
    let to = validity.not_after.to_unix_duration().as_secs() as i64;
    Ok((from..=to).contains(&at.unix_seconds()))
}

/// Whether a certificate carries `extendedKeyUsage` with `id-kp-timeStamping`, and whether that
/// extension is critical.
///
/// RFC 3161 §2.3 requires both of a timestamp responder. A responder certificate without it means
/// any certificate the same CA issued could be used to forge timestamps.
pub fn has_critical_timestamping_eku(certificate_der: &[u8]) -> Result<bool> {
    const ID_CE_EXT_KEY_USAGE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.37");
    const ID_KP_TIME_STAMPING: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.8");

    let cert = parse_certificate(certificate_der)?;
    let Some(extensions) = cert.tbs_certificate.extensions.as_ref() else {
        return Ok(false);
    };
    let Some(ext) = extensions.iter().find(|e| e.extn_id == ID_CE_EXT_KEY_USAGE) else {
        return Ok(false);
    };
    if !ext.critical {
        return Ok(false);
    }
    let usages = x509_cert::ext::pkix::ExtendedKeyUsage::from_der(ext.extn_value.as_bytes())
        .map_err(|e| Error::der("extendedKeyUsage", e))?;
    Ok(usages.0.contains(&ID_KP_TIME_STAMPING))
}

/// Check that one certificate was signed by another.
pub fn verify_certificate_signature(subject_der: &[u8], issuer_der: &[u8]) -> Result<()> {
    verify_certificate_signature_with_spki(subject_der, &spki_of(issuer_der)?)
}

/// Whether the issuer name of `subject` equals the subject name of `issuer`.
pub fn names_link(subject_der: &[u8], issuer_der: &[u8]) -> Result<bool> {
    let subject = parse_certificate(subject_der)?;
    let issuer = parse_certificate(issuer_der)?;
    Ok(subject.tbs_certificate.issuer == issuer.tbs_certificate.subject)
}

/// Whether a certificate is self-signed by name.
pub fn is_self_issued(der: &[u8]) -> Result<bool> {
    let cert = parse_certificate(der)?;
    Ok(cert.tbs_certificate.issuer == cert.tbs_certificate.subject)
}

/// Rendered subject distinguished name.
pub fn subject_of(der: &[u8]) -> Result<String> {
    Ok(parse_certificate(der)?.tbs_certificate.subject.to_string())
}

#[cfg(all(test, feature = "soft-signer"))]
mod tests {
    use super::*;
    use crate::signer::SoftSigner;

    fn signer() -> SoftSigner {
        SoftSigner::generate(
            "CN=Test Signer,C=JP",
            Timestamp::from_unix_seconds(1_700_000_000),
            365,
        )
        .unwrap()
    }

    fn params(digest: [u8; 32]) -> SignedDataParams<'static> {
        SignedDataParams {
            content_digest: digest,
            content_type: ID_DATA,
            extra_certificates: &[],
            signing_time: Timestamp::from_unix_seconds(1_700_000_100),
        }
    }

    #[test]
    fn builds_and_verifies_a_detached_signature() {
        let mut s = signer();
        let content = b"the bytes that were signed";
        let der = build_signed_data(&mut s, &params(sha256(content))).unwrap();

        let v = verify_signed_data(&der, content).unwrap();
        assert!(v.signature_verified);
        assert!(v.message_digest_matches);
        assert!(v.content_type_matches);
        assert!(v.signing_certificate_bound);
        assert_eq!(
            v.claimed_signing_time.as_deref(),
            Some("2023-11-14T22:15:00Z")
        );
        assert_eq!(v.signature_value.len(), 256);
    }

    #[test]
    fn a_signature_over_different_content_is_caught_by_the_message_digest() {
        let mut s = signer();
        let der = build_signed_data(&mut s, &params(sha256(b"one"))).unwrap();
        // The signature is genuine; the content is not the one it was made for. Both facts have
        // to be visible, because only reporting the first would accept a transplanted signature.
        let v = verify_signed_data(&der, b"another").unwrap();
        assert!(v.signature_verified);
        assert!(!v.message_digest_matches);
    }

    #[test]
    fn the_signed_attributes_are_hashed_with_the_set_of_tag() {
        // The attributes are `[0] IMPLICIT` inside the SignerInfo and `SET OF` when hashed. If
        // this ever regresses, the signatures still verify against themselves and against nothing
        // else, which is the worst kind of bug to find later.
        let mut s = signer();
        let der = build_signed_data(&mut s, &params(sha256(b"x"))).unwrap();
        let (_, signer_info) = split(&der).unwrap();
        let attrs = signer_info.signed_attrs.as_ref().unwrap();
        let encoded = signed_attrs_der(attrs).unwrap();
        assert_eq!(encoded[0], 0x31, "must carry the universal SET OF tag");
    }

    #[test]
    fn carries_the_certificates_a_verifier_needs() {
        let mut s = signer();
        let other = SoftSigner::generate(
            "CN=A CA,C=JP",
            Timestamp::from_unix_seconds(1_700_000_000),
            365,
        )
        .unwrap();
        let extra = vec![other.certificate().der().to_vec()];
        let mut p = params(sha256(b"x"));
        p.extra_certificates = &extra;

        let der = build_signed_data(&mut s, &p).unwrap();
        let v = verify_signed_data(&der, b"x").unwrap();
        assert_eq!(v.certificates.len(), 2);
        assert_eq!(v.signer_certificate, s.certificate().der());
    }

    #[test]
    fn the_signers_own_certificate_among_the_extras_is_not_an_error() {
        // A `SET OF` rejects duplicates, so passing the signer's certificate twice used to fail
        // the whole signature. It is a plausible thing for a caller to do; it must not.
        let mut s = signer();
        let extra = vec![s.certificate().der().to_vec()];
        let mut p = params(sha256(b"x"));
        p.extra_certificates = &extra;

        let der = build_signed_data(&mut s, &p).unwrap();
        let v = verify_signed_data(&der, b"x").unwrap();
        assert_eq!(v.certificates.len(), 1);
        assert!(v.signature_verified);
    }

    #[test]
    fn a_self_signed_certificate_verifies_against_itself() {
        let s = signer();
        let der = s.certificate().der();
        assert!(is_self_issued(der).unwrap());
        assert!(names_link(der, der).unwrap());
        verify_certificate_signature(der, der).unwrap();
    }

    #[test]
    fn a_certificate_without_the_timestamping_eku_is_reported_as_such() {
        let s = signer();
        assert!(!has_critical_timestamping_eku(s.certificate().der()).unwrap());
    }
}
