//! OpenPGP signatures made with the card's key.
//!
//! # The key
//!
//! An OpenPGP key ID is a hash of the key material *and its creation time*, so a creation time
//! taken from the clock would give the same card a different identity every run. The creation time
//! is therefore fixed to the signing certificate's `notBefore`: one card, one certificate, one
//! fingerprint, reproducibly. A renewed certificate is a new key, which is the right answer — it
//! is a new key pair.
//!
//! # The X.509 certificate travels with the signature
//!
//! An OpenPGP signature on its own says only that some RSA key made it. What ties that key to a
//! person is the JPKI certificate, so it is carried in a notation subpacket and the verifier
//! checks that the two hold the same modulus ([`verify_detached`]). Without that check the
//! certificate would be decoration.
//!
//! **The certificate discloses the holder's 氏名, 住所, 生年月日 and 性別.** Embedding it means
//! publishing them. [`SignOptions::embed_certificate`] can turn it off, and the caller is expected
//! to have shown the user what is in there first; see [`crate::x509::Holder`].
//!
//! # Streaming
//!
//! Documents are hashed through [`sequoia_openpgp::crypto::hash::Context`] rather than read into
//! memory, so signing a large file costs a buffer and not the file.

use std::io::Read;

use sequoia_openpgp::armor;
use sequoia_openpgp::cert::Cert;
use sequoia_openpgp::crypto::{Signer as PgpSignerTrait, mpi};
use sequoia_openpgp::packet::key::{PublicParts, UnspecifiedRole};
use sequoia_openpgp::packet::signature::SignatureBuilder;
use sequoia_openpgp::packet::{Key, Packet, Signature, UserID, key::Key4};
use sequoia_openpgp::parse::Parse;
use sequoia_openpgp::serialize::Serialize as _;
use sequoia_openpgp::types::{HashAlgorithm, SignatureType};
use serde::Serialize;

use crate::error::{Error, Result};
use crate::signer::DigestSigner;
use crate::time::Timestamp;
use crate::x509::{CertificateInfo, ReferenceDate, TrustCheck};

/// Notation carrying the signer's X.509 certificate, DER.
pub const X509_NOTATION: &str = "x509-certificate@myna-sign";

/// Notation carrying an RFC 3161 timestamp token over this signature, DER.
///
/// Lives in the **unhashed** subpacket area: the token is made from the finished signature, so the
/// signature cannot cover it. See [`crate::tsa`] for what the token is computed over.
pub const TIMESTAMP_NOTATION: &str = "timestamp-token@myna-sign";

/// The only digest the card can sign, and so the only one used here.
static ACCEPTABLE_HASHES: [HashAlgorithm; 1] = [HashAlgorithm::SHA256];

/// Derive the OpenPGP public key that corresponds to a JPKI certificate.
///
/// The creation time is the certificate's `notBefore`, which is what makes the result
/// reproducible.
pub fn derive_key(
    certificate: &myna_card::Certificate,
) -> Result<Key<PublicParts, UnspecifiedRole>> {
    let key = certificate.public_key()?;
    let created = not_before(certificate)?;
    let key4 = Key4::import_public_rsa(&key.exponent, &key.modulus, created.to_system_time()?)
        .map_err(|e| {
            Error::malformed(format!(
                "the certificate's key is not usable as an OpenPGP key: {e}"
            ))
        })?;
    Ok(Key::from(key4))
}

/// The certificate's `notBefore`, to the second.
///
/// `myna-card`'s [`Certificate::validity`] drops the time of day, which would be enough for a
/// calendar comparison but not for a fingerprint: two keys whose creation times differ by hours
/// have different fingerprints, so the seconds have to survive.
///
/// [`Certificate::validity`]: myna_card::Certificate::validity
fn not_before(certificate: &myna_card::Certificate) -> Result<Timestamp> {
    let seconds = certificate
        .inner()
        .tbs_certificate()
        .validity()
        .not_before
        .to_unix_duration()
        .as_secs();
    Ok(Timestamp::from_unix_seconds(seconds as i64))
}

/// A [`DigestSigner`] dressed as the signer sequoia wants.
struct PgpSigner<'a, S: DigestSigner + ?Sized> {
    inner: &'a mut S,
    key: Key<PublicParts, UnspecifiedRole>,
}

impl<'a, S: DigestSigner + ?Sized> PgpSigner<'a, S> {
    fn new(inner: &'a mut S) -> Result<Self> {
        let key = derive_key(inner.certificate())?;
        Ok(PgpSigner { inner, key })
    }
}

impl<S: DigestSigner + ?Sized> PgpSignerTrait for PgpSigner<'_, S> {
    fn public(&self) -> &Key<PublicParts, UnspecifiedRole> {
        &self.key
    }

    /// SHA-256 only.
    ///
    /// The default implementation accepts every hash sequoia knows, and the first time it picked
    /// SHA-512 the card would be handed 64 bytes and refuse. Narrowing it here means sequoia
    /// chooses something the card can actually sign.
    fn acceptable_hashes(&self) -> &[HashAlgorithm] {
        &ACCEPTABLE_HASHES
    }

    fn sign(
        &mut self,
        _algo: HashAlgorithm,
        digest: &[u8],
    ) -> sequoia_openpgp::Result<mpi::Signature> {
        let digest: &[u8; 32] = digest.try_into().map_err(|_| {
            sequoia_openpgp::Error::InvalidOperation(format!(
                "the card signs 32 byte digests, not {}",
                digest.len()
            ))
        })?;
        let signature = self
            .inner
            .sign_sha256_checked(digest)
            .map_err(|e| sequoia_openpgp::Error::InvalidOperation(e.to_string()))?;
        Ok(mpi::Signature::RSA {
            s: mpi::MPI::new(&signature),
        })
    }
}

/// What to put in a signature.
#[derive(Debug, Clone)]
pub struct SignOptions {
    /// Embed the signer's X.509 certificate, so the `.asc` verifies on its own.
    ///
    /// **This discloses the holder's 基本4情報.** Default `true`; the caller is expected to have
    /// confirmed that with the user.
    pub embed_certificate: bool,
    /// The signature's creation time. Defaults to now.
    pub created: Option<Timestamp>,
}

impl Default for SignOptions {
    fn default() -> Self {
        SignOptions {
            embed_certificate: true,
            created: None,
        }
    }
}

/// Start a signature builder with the creation time and, if asked, the certificate notation.
fn builder_for<S: DigestSigner + ?Sized>(
    pgp: &PgpSigner<'_, S>,
    kind: SignatureType,
    options: &SignOptions,
) -> Result<SignatureBuilder> {
    let created = match options.created {
        Some(t) => t,
        None => Timestamp::now()?,
    };

    let mut builder = SignatureBuilder::new(kind)
        .set_signature_creation_time(created.to_system_time()?)
        .map_err(pgp_err("setting the creation time"))?;

    if options.embed_certificate {
        builder = builder
            .add_notation(
                X509_NOTATION,
                pgp.inner.certificate().der(),
                None,
                false, // not critical: other OpenPGP tools should ignore it, not choke on it
            )
            .map_err(pgp_err("adding the certificate notation"))?;
    }
    Ok(builder)
}

/// Sign a document, producing an armored detached signature.
///
/// Returns the `.asc` bytes and the raw signature packet, the latter so that a caller adding a
/// timestamp can compute the imprint without re-parsing.
pub fn sign_detached<S: DigestSigner + ?Sized, R: Read>(
    signer: &mut S,
    document: R,
    options: &SignOptions,
) -> Result<DetachedSignature> {
    let mut pgp = PgpSigner::new(signer)?;
    let builder = builder_for(&pgp, SignatureType::Binary, options)?;

    let context = hash_document(document)?;
    let signature = builder
        .sign_hash(&mut pgp, context)
        .map_err(pgp_err("signing"))?;

    Ok(DetachedSignature {
        armored: armor_signature(&signature)?,
        signature,
        cleartext: None,
    })
}

/// A finished signature, detached or cleartext.
pub struct DetachedSignature {
    /// The `.asc` bytes.
    pub armored: Vec<u8>,
    /// The signature packet, for a caller that wants to timestamp it.
    pub signature: Signature,
    /// The canonical text, when this is a cleartext signed message.
    ///
    /// Kept so that [`DetachedSignature::attach_timestamp`] can put the framing back. Re-armoring
    /// a cleartext message as a bare signature would throw the text away, which is exactly what
    /// the first version of this did.
    cleartext: Option<String>,
}

impl DetachedSignature {
    /// The raw RSA signature value, which is what an RFC 3161 timestamp is computed over.
    ///
    /// See [`crate::tsa`] — this mirrors CMS, where the timestamp covers `signerInfo.signature`.
    pub fn signature_value(&self) -> Result<Vec<u8>> {
        match self.signature.mpis() {
            mpi::Signature::RSA { s } => Ok(s.value().to_vec()),
            _ => Err(Error::malformed("the signature is not RSA")),
        }
    }

    /// Attach a timestamp token and re-armor.
    ///
    /// The token goes in the unhashed area, which is the only place it can go: it is made from
    /// the finished signature and so cannot be covered by it.
    pub fn attach_timestamp(&mut self, token_der: &[u8]) -> Result<()> {
        use sequoia_openpgp::packet::signature::subpacket::{
            NotationData, NotationDataFlags, Subpacket, SubpacketValue,
        };

        let subpacket = Subpacket::new(
            SubpacketValue::NotationData(NotationData::new(
                TIMESTAMP_NOTATION,
                token_der,
                NotationDataFlags::empty(),
            )),
            false,
        )
        .map_err(pgp_err("building the timestamp notation"))?;
        self.signature
            .unhashed_area_mut()
            .add(subpacket)
            .map_err(pgp_err("adding the timestamp notation"))?;

        let armored = armor_signature(&self.signature)?;
        self.armored = match &self.cleartext {
            Some(canonical) => frame_cleartext(canonical, &armored),
            None => armored,
        };
        Ok(())
    }
}

// --- Cleartext signatures ---------------------------------------------------------------------

/// Sign text so that the signature travels inside it, readable.
///
/// The result is a cleartext signed message (RFC 9580 §7): the text, then the signature, in one
/// file that a person can still read. For a plain text document that is often what is wanted —
/// a `.asc` beside the file is easy to lose, and this cannot be separated from what it signs.
///
/// # What is actually signed
///
/// Not the bytes as given. A cleartext signature is computed over the text **canonicalised**:
/// trailing spaces and tabs removed from every line, lines joined with CRLF, and no line ending
/// after the last line. That is what makes the format survive being pasted into mail, and it is
/// also why trailing whitespace cannot be signed — the canonical form is written out, so what the
/// file contains is what was signed.
///
/// Lines beginning with `-` are dash-escaped on the way out, as the format requires, and that
/// escaping is not part of what is hashed.
pub fn sign_cleartext<S: DigestSigner + ?Sized>(
    signer: &mut S,
    text: &str,
    options: &SignOptions,
) -> Result<DetachedSignature> {
    let canonical = canonicalise(text);

    let mut pgp = PgpSigner::new(signer)?;
    let builder = builder_for(&pgp, SignatureType::Text, options)?;

    let mut context = HashAlgorithm::SHA256
        .context()
        .map_err(pgp_err("starting a SHA-256 context"))?
        .for_signature(4);
    context.update(canonical.as_bytes());

    let signature = builder
        .sign_hash(&mut pgp, context)
        .map_err(pgp_err("signing"))?;

    Ok(DetachedSignature {
        armored: frame_cleartext(&canonical, &armor_signature(&signature)?),
        signature,
        cleartext: Some(canonical),
    })
}

/// The form a cleartext signature is computed over.
fn canonicalise(text: &str) -> String {
    text.split('\n')
        .map(|line| line.trim_end_matches(['\r', ' ', '\t']))
        .collect::<Vec<_>>()
        .join("\r\n")
}

/// Wrap canonical text and an armored signature in the cleartext framing.
fn frame_cleartext(canonical: &str, armored_signature: &[u8]) -> Vec<u8> {
    let mut out = String::from("-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\n");
    for line in canonical.split("\r\n") {
        // Dash-escaping: a line that starts with `-` would otherwise be mistaken for the armor
        // that follows. The escape is added here and is not part of what was hashed.
        if line.starts_with('-') {
            out.push_str("- ");
        }
        out.push_str(line);
        out.push('\n');
    }
    let mut bytes = out.into_bytes();
    bytes.extend_from_slice(armored_signature);
    bytes
}

/// Read a cleartext signed message back into its text and its signature.
///
/// Returns the canonical text — the bytes the signature covers — so a verifier can hash it
/// without repeating the canonicalisation rules.
pub fn split_cleartext(message: &[u8]) -> Result<(String, Vec<u8>)> {
    let text = std::str::from_utf8(message)
        .map_err(|_| Error::malformed("a cleartext signed message must be text"))?;

    let body = text
        .split_once("-----BEGIN PGP SIGNED MESSAGE-----")
        .ok_or_else(|| Error::malformed("not a cleartext signed message"))?
        .1;
    // The headers run to the first blank line.
    let body = body
        .split_once("\n\n")
        .or_else(|| body.split_once("\r\n\r\n"))
        .ok_or_else(|| Error::malformed("no blank line after the cleartext headers"))?
        .1;
    let (cleartext, signature) = body
        .split_once("-----BEGIN PGP SIGNATURE-----")
        .ok_or_else(|| Error::malformed("no signature in the cleartext message"))?;

    // Undo the dash-escaping, then canonicalise: the same text the signer hashed.
    let unescaped: Vec<&str> = cleartext
        .split('\n')
        .map(|line| line.strip_prefix("- ").unwrap_or(line))
        .collect();
    // The newline before the armor belongs to the framing, not to the text.
    let trimmed = match unescaped.split_last() {
        Some((last, rest)) if last.trim().is_empty() => rest.join("\n"),
        _ => unescaped.join("\n"),
    };

    let armored = format!("-----BEGIN PGP SIGNATURE-----{signature}");
    Ok((canonicalise(&trimmed), armored.into_bytes()))
}

/// Verify a cleartext signed message.
pub fn verify_cleartext(message: &[u8], options: &VerifyOptions) -> Result<PgpVerification> {
    let (canonical, armored) = split_cleartext(message)?;
    verify_detached(&armored, canonical.as_bytes(), options)
}

/// Export the signer's public key as an OpenPGP certificate, so `gpg` can verify.
///
/// Costs one extra card signature: the user ID binding has to be made by the key itself. The
/// binding's creation time is the key's, so the whole certificate is byte-reproducible.
///
/// `user_id` is shown by every OpenPGP tool that imports this. It defaults to the certificate's
/// `CN` at the call site, and the user can edit it — the point being not to put an address in it
/// by accident.
pub fn export_certificate<S: DigestSigner + ?Sized>(
    signer: &mut S,
    user_id: &str,
) -> Result<Vec<u8>> {
    let created = not_before(signer.certificate())?;
    let mut pgp = PgpSigner::new(signer)?;
    let primary = pgp.key.clone().role_into_primary();
    let uid = UserID::from(user_id);

    let binding = SignatureBuilder::new(SignatureType::PositiveCertification)
        .set_signature_creation_time(created.to_system_time()?)
        .map_err(pgp_err("setting the binding creation time"))?
        .set_hash_algo(HashAlgorithm::SHA256)
        .sign_userid_binding(&mut pgp, Some(&primary), &uid)
        .map_err(pgp_err("signing the user ID binding"))?;

    let cert = Cert::try_from(vec![
        Packet::PublicKey(primary),
        Packet::from(uid),
        Packet::from(binding),
    ])
    .map_err(pgp_err("assembling the certificate"))?;

    let mut writer = armor::Writer::new(Vec::new(), armor::Kind::PublicKey)
        .map_err(|e| Error::io("armoring the certificate", e))?;
    cert.serialize(&mut writer)
        .map_err(pgp_err("serializing the certificate"))?;
    writer
        .finalize()
        .map_err(|e| Error::io("finishing the armor", e))
}

// ---------------------------------------------------------------------------------------------

/// What to accept when verifying.
#[derive(Debug, Clone, Default)]
pub struct VerifyOptions {
    /// A certificate supplied out of band, used when the signature carries none.
    pub certificate: Option<myna_card::Certificate>,
    /// Whether to accept the JPKI test hierarchy.
    ///
    /// Off by default, and that default is the point: a test card is not a person's Individual
    /// Number Card, and nothing should accept one without being asked to.
    pub accept_test_hierarchy: bool,
}

/// The result of checking a detached signature.
///
/// Every field is reported separately and none of them is called "valid". A caller that wants to
/// present a single verdict has to decide what it means; this type will not decide for it.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PgpVerification {
    /// Whether the signature verifies under the key.
    pub signature_verified: bool,
    /// When the signature says it was made. Not evidence of anything on its own — the signer
    /// chose it. [`PgpVerification::timestamp`] is the part a third party attested.
    pub claimed_creation_time: Option<String>,
    /// The signer's certificate, if one was available.
    pub certificate: Option<CertificateInfo>,
    /// Whether the OpenPGP key and the X.509 certificate are the same key.
    ///
    /// `false` means the embedded certificate names someone other than whoever made the
    /// signature, and the identity in it must not be shown.
    pub key_matches_certificate: bool,
    /// How far the certificate was checked.
    pub trust: Option<TrustCheck>,
    /// The verified RFC 3161 timestamp, if the signature carried one.
    pub timestamp: Option<crate::tsa::TimestampVerification>,
}

/// Verify a detached signature over a document.
///
/// `Err` is for inputs that could not be examined at all — armor that will not parse, a signature
/// packet that is not there. A signature that simply does not verify comes back as a
/// [`PgpVerification`] saying so.
pub fn verify_detached<R: Read>(
    armored_signature: &[u8],
    document: R,
    options: &VerifyOptions,
) -> Result<PgpVerification> {
    let signature = parse_signature(armored_signature)?;

    // The certificate that came with the signature, if any, else the one the caller supplied.
    let embedded = embedded_certificate(&signature)?;
    let certificate = embedded.or_else(|| options.certificate.clone());

    let Some(certificate) = certificate else {
        return Err(Error::NotChecked(
            "the signature carries no certificate and none was supplied, so there is no key to \
             check it against"
                .into(),
        ));
    };

    let key = derive_key(&certificate)?;
    let context = hash_document(document)?;
    let signature_verified = signature.verify_hash(&key, context).is_ok();

    // The certificate is only worth reading if it belongs to the key that signed. Otherwise it is
    // someone else's certificate stapled to this signature, and showing its holder would name the
    // wrong person.
    let key_matches_certificate = signature_verified;

    let timestamp = verify_embedded_timestamp(&signature, options)?;
    let reference = match &timestamp {
        Some(ts) if ts.verified => {
            ReferenceDate::from_timestamp(Timestamp::from_unix_seconds(ts.gen_time_unix))
        }
        _ => ReferenceDate::now()?,
    };

    let accept = if options.accept_test_hierarchy {
        myna_card::certificate::roots::Accept::ProductionAndTest
    } else {
        myna_card::certificate::roots::Accept::ProductionOnly
    };

    Ok(PgpVerification {
        signature_verified,
        claimed_creation_time: signature
            .signature_creation_time()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| Timestamp::from_unix_seconds(d.as_secs() as i64).to_rfc3339()),
        certificate: Some(CertificateInfo::read(&certificate)?),
        key_matches_certificate,
        trust: Some(crate::x509::check_to_root(&certificate, reference, accept)?),
        timestamp,
    })
}

/// The X.509 certificate a signature carries, if it carries one.
pub fn embedded_certificate(signature: &Signature) -> Result<Option<myna_card::Certificate>> {
    for notation in signature.notation_data() {
        if notation.name() == X509_NOTATION {
            return Ok(Some(myna_card::Certificate::parse(notation.value())?));
        }
    }
    Ok(None)
}

/// The RFC 3161 token a signature carries, if it carries one.
///
/// Looks in the **unhashed** area explicitly. `Signature::notation_data` deliberately returns only
/// notations from the hashed area — a notation in the unhashed area is not covered by the signature
/// and sequoia will not hand it out as if it were. That is the right default and the wrong one
/// here: a timestamp is made *from* the finished signature, so the unhashed area is the only place
/// it can live. Reading it takes saying so.
pub fn embedded_timestamp(signature: &Signature) -> Option<&[u8]> {
    use sequoia_openpgp::packet::signature::subpacket::SubpacketValue;

    signature
        .unhashed_area()
        .iter()
        .find_map(|subpacket| match subpacket.value() {
            SubpacketValue::NotationData(notation) if notation.name() == TIMESTAMP_NOTATION => {
                Some(notation.value())
            }
            _ => None,
        })
}

fn verify_embedded_timestamp(
    signature: &Signature,
    options: &VerifyOptions,
) -> Result<Option<crate::tsa::TimestampVerification>> {
    let Some(token) = embedded_timestamp(signature) else {
        return Ok(None);
    };
    let mpi::Signature::RSA { s } = signature.mpis() else {
        return Ok(None);
    };
    let _ = options;
    Ok(Some(crate::tsa::verify_token(token, s.value())?))
}

/// Parse an armored detached signature down to its signature packet.
fn parse_signature(armored: &[u8]) -> Result<Signature> {
    use sequoia_openpgp::PacketPile;

    let pile = PacketPile::from_bytes(armored)
        .map_err(|e| Error::malformed(format!("not an OpenPGP signature: {e}")))?;
    pile.into_children()
        .find_map(|p| match p {
            Packet::Signature(s) => Some(s),
            _ => None,
        })
        .ok_or_else(|| Error::malformed("no signature packet in the input"))
}

/// Hash a document the way an OpenPGP v4 binary signature wants it.
fn hash_document<R: Read>(mut document: R) -> Result<sequoia_openpgp::crypto::hash::Context> {
    let mut context = HashAlgorithm::SHA256
        .context()
        .map_err(pgp_err("starting a SHA-256 context"))?
        .for_signature(4);

    let mut buffer = vec![0u8; 64 * 1024];
    loop {
        let n = document
            .read(&mut buffer)
            .map_err(|e| Error::io("reading the document", e))?;
        if n == 0 {
            break;
        }
        context.update(&buffer[..n]);
    }
    Ok(context)
}

fn armor_signature(signature: &Signature) -> Result<Vec<u8>> {
    let mut writer = armor::Writer::new(Vec::new(), armor::Kind::Signature)
        .map_err(|e| Error::io("armoring the signature", e))?;
    Packet::from(signature.clone())
        .serialize(&mut writer)
        .map_err(pgp_err("serializing the signature"))?;
    writer
        .finalize()
        .map_err(|e| Error::io("finishing the armor", e))
}

/// Turn a sequoia error into ours, saying what was being attempted.
fn pgp_err(context: &'static str) -> impl Fn(anyhow::Error) -> Error {
    move |e| Error::malformed(format!("{context}: {e}"))
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

    #[test]
    fn the_key_is_the_same_every_time_it_is_derived() {
        let s = signer();
        let a = derive_key(s.certificate()).unwrap();
        let b = derive_key(s.certificate()).unwrap();
        assert_eq!(a.fingerprint(), b.fingerprint());
        // And it is the certificate's notBefore that fixes it, not the clock.
        assert_eq!(
            a.creation_time(),
            Timestamp::from_unix_seconds(1_700_000_000)
                .to_system_time()
                .unwrap()
        );
    }

    #[test]
    fn signs_and_verifies_a_document() {
        let mut s = signer();
        let doc = b"the document that was signed";
        let sig = sign_detached(&mut s, &doc[..], &SignOptions::default()).unwrap();
        assert!(sig.armored.starts_with(b"-----BEGIN PGP SIGNATURE-----"));

        let v = verify_detached(&sig.armored, &doc[..], &VerifyOptions::default()).unwrap();
        assert!(v.signature_verified);
        assert!(v.key_matches_certificate);
        assert_eq!(
            v.certificate.as_ref().unwrap().common_name.as_deref(),
            Some("Test Signer")
        );
    }

    #[test]
    fn a_changed_document_does_not_verify() {
        let mut s = signer();
        let sig = sign_detached(&mut s, &b"original"[..], &SignOptions::default()).unwrap();
        let v = verify_detached(&sig.armored, &b"tampered"[..], &VerifyOptions::default()).unwrap();
        assert!(!v.signature_verified);
    }

    #[test]
    fn without_the_notation_there_is_nothing_to_check_against() {
        let mut s = signer();
        let options = SignOptions {
            embed_certificate: false,
            ..Default::default()
        };
        let sig = sign_detached(&mut s, &b"doc"[..], &options).unwrap();
        // The signature is fine, but on its own it names no one.
        assert!(matches!(
            verify_detached(&sig.armored, &b"doc"[..], &VerifyOptions::default()),
            Err(Error::NotChecked(_))
        ));
        // Supplied out of band, it verifies.
        let options = VerifyOptions {
            certificate: Some(s.certificate().clone()),
            ..Default::default()
        };
        let v = verify_detached(&sig.armored, &b"doc"[..], &options).unwrap();
        assert!(v.signature_verified);
    }

    #[test]
    fn a_certificate_from_a_different_key_is_not_taken_as_the_signer() {
        let mut a = signer();
        let b = SoftSigner::generate(
            "CN=Someone Else,C=JP",
            Timestamp::from_unix_seconds(1_700_000_000),
            365,
        )
        .unwrap();

        let sig = sign_detached(&mut a, &b"doc"[..], &SignOptions::default()).unwrap();
        // Check the signature against the wrong certificate: it must not verify, so nothing
        // downstream may present "Someone Else" as the signer.
        let options = VerifyOptions {
            certificate: Some(b.certificate().clone()),
            ..Default::default()
        };
        let sig_no_notation = sign_detached(
            &mut a,
            &b"doc"[..],
            &SignOptions {
                embed_certificate: false,
                ..Default::default()
            },
        )
        .unwrap();
        let _ = sig;
        let v = verify_detached(&sig_no_notation.armored, &b"doc"[..], &options).unwrap();
        assert!(!v.signature_verified);
        assert!(!v.key_matches_certificate);
    }

    #[test]
    fn exports_a_certificate_gpg_can_read() {
        let mut s = signer();
        let armored = export_certificate(&mut s, "Test Signer <test@example.invalid>").unwrap();
        assert!(armored.starts_with(b"-----BEGIN PGP PUBLIC KEY BLOCK-----"));
        let cert = Cert::from_bytes(&armored).unwrap();
        assert_eq!(cert.userids().count(), 1);
        assert_eq!(
            cert.fingerprint(),
            derive_key(s.certificate()).unwrap().fingerprint()
        );
    }
}
