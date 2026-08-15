//! Checking the signatures in a PDF.
//!
//! # The check that matters
//!
//! `/ByteRange` says which bytes the signature covers. Nothing forces it to cover all of them, and
//! a signature that leaves a gap is the classic way to hide content in a "signed" document: put
//! the real page outside the range, and every viewer that only checks the digest over what the
//! range names will call it valid.
//!
//! So two things are checked separately and reported separately:
//!
//! - the gap in the range is *exactly* the `/Contents` hex string and nothing else
//!   ([`PdfSignatureVerification::byte_range_sound`]), and
//! - the range reaches the end of the file
//!   ([`PdfSignatureVerification::covers_whole_file`]).
//!
//! The second is legitimately false when a later revision was appended — that is how a second
//! signature works — so it is a fact about scope, not a verdict. The first being false means the
//! document is lying about what it signed.

use lopdf::{Document, Object, ObjectId};
use serde::Serialize;

use crate::cms;
use crate::error::{Error, Result};
use crate::time::Timestamp;
use crate::tsa::{self, TimestampVerification, TrustAnchors};
use crate::x509::{self, CertificateInfo, ReferenceDate, TrustCheck};

/// What to accept when verifying.
#[derive(Debug, Clone, Default)]
pub struct VerifyOptions {
    /// Accept the JPKI test hierarchy. Off unless the user asked for it: a test card is not a
    /// person's Individual Number Card.
    pub accept_test_hierarchy: bool,
    /// Trust anchors for any timestamp tokens found. Defaults to everything this program knows.
    pub timestamp_anchors: Option<TrustAnchors>,
}

/// One signature in a PDF, and everything that could be established about it.
///
/// There is no single "valid" field. A caller that wants one has to decide what it means from
/// these, which is the point: "the signature verifies" and "the document has not changed" and
/// "the signer is who the certificate says" are different claims and fail independently.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PdfSignatureVerification {
    /// The field's `/T`.
    pub field_name: Option<String>,
    /// `/Name`, as the signer wrote it. Not evidence — [`Self::certificate`] is.
    pub claimed_name: Option<String>,
    /// `/Reason`.
    pub reason: Option<String>,
    /// `/Location`.
    pub location: Option<String>,
    /// `/M`, the claimed signing time, as RFC 3339.
    ///
    /// Read out of the PDF's own date format and converted to UTC, so that everything the
    /// interface displays is the same shape and it can show them in one timezone.
    pub claimed_signing_time: Option<String>,
    /// The CMS signature verifies under the signer's certificate.
    pub signature_verified: bool,
    /// The digest in the signature matches the bytes the `/ByteRange` names.
    pub document_digest_matches: bool,
    /// The `/ByteRange` leaves out exactly the `/Contents` string and nothing else.
    ///
    /// `false` means content was hidden outside the signed range. This is the check that stops a
    /// forged document reading as signed.
    pub byte_range_sound: bool,
    /// The `/ByteRange` reaches the end of the file.
    ///
    /// `false` means something was appended after this signature — a later signature, or an edit.
    /// Legitimate in a multiply signed document; see [`Self::bytes_after`].
    pub covers_whole_file: bool,
    /// How many bytes follow what this signature covers.
    pub bytes_after: usize,
    /// The signer's certificate.
    pub certificate: Option<CertificateInfo>,
    /// How far the certificate was checked, and on what date.
    pub trust: Option<TrustCheck>,
    /// The RFC 3161 timestamp, if the signature carried one.
    pub timestamp: Option<TimestampVerification>,
    /// `signingCertificateV2` is present and names the certificate that was used.
    pub signing_certificate_bound: bool,
}

/// Verify every signature in a PDF, in the order the fields appear.
pub fn verify(bytes: &[u8], options: &VerifyOptions) -> Result<Vec<PdfSignatureVerification>> {
    let document = Document::load_mem(bytes)
        .map_err(|e| Error::malformed(format!("not a PDF this program can read: {e}")))?;

    let mut results = Vec::new();
    for field_id in signature_field_ids(&document) {
        results.push(verify_field(&document, field_id, bytes, options)?);
    }
    Ok(results)
}

/// The `/ByteRange` of the first signature, as four numbers.
///
/// Exposed for tests and for a caller that wants to show the spans without verifying.
pub fn byte_range_of(bytes: &[u8]) -> Result<[usize; 4]> {
    let document = Document::load_mem(bytes)
        .map_err(|e| Error::malformed(format!("not a PDF this program can read: {e}")))?;
    let field_id = signature_field_ids(&document)
        .into_iter()
        .next()
        .ok_or_else(|| Error::malformed("the document carries no signature"))?;
    let signature = signature_dictionary(&document, field_id)?;
    read_byte_range(&document, signature)
}

/// The signature fields, in `/AcroForm /Fields` order.
pub(crate) fn signature_field_ids(document: &Document) -> Vec<ObjectId> {
    let Ok(catalog) = document.catalog() else {
        return Vec::new();
    };
    let Some(acroform) = catalog
        .get(b"AcroForm")
        .ok()
        .and_then(|o| resolve_dictionary(document, o))
    else {
        return Vec::new();
    };
    let Ok(Object::Array(fields)) = acroform.get(b"Fields") else {
        return Vec::new();
    };

    fields
        .iter()
        .filter_map(|o| match o {
            Object::Reference(id) => Some(*id),
            _ => None,
        })
        .filter(|id| {
            document
                .get_dictionary(*id)
                .ok()
                .and_then(|d| d.get(b"FT").ok())
                .and_then(|o| o.as_name().ok())
                .map(|n| n == b"Sig")
                .unwrap_or(false)
        })
        .collect()
}

fn resolve_dictionary<'a>(
    document: &'a Document,
    object: &'a Object,
) -> Option<&'a lopdf::Dictionary> {
    match object {
        Object::Dictionary(d) => Some(d),
        Object::Reference(id) => document.get_dictionary(*id).ok(),
        _ => None,
    }
}

fn signature_dictionary(document: &Document, field_id: ObjectId) -> Result<&lopdf::Dictionary> {
    let field = document
        .get_dictionary(field_id)
        .map_err(|e| Error::malformed(format!("signature field {field_id:?}: {e}")))?;
    let value = field
        .get(b"V")
        .map_err(|_| Error::malformed("the signature field has no /V"))?;
    resolve_dictionary(document, value)
        .ok_or_else(|| Error::malformed("the signature field's /V is not a dictionary"))
}

fn read_byte_range(document: &Document, signature: &lopdf::Dictionary) -> Result<[usize; 4]> {
    let array = signature
        .get(b"ByteRange")
        .ok()
        .and_then(|o| match o {
            Object::Array(items) => Some(items.clone()),
            Object::Reference(id) => match document.get_object(*id) {
                Ok(Object::Array(items)) => Some(items.clone()),
                _ => None,
            },
            _ => None,
        })
        .ok_or_else(|| Error::malformed("the signature has no /ByteRange array"))?;

    if array.len() != 4 {
        return Err(Error::malformed(format!(
            "/ByteRange has {} entries, not four",
            array.len()
        )));
    }
    let mut out = [0usize; 4];
    for (slot, object) in out.iter_mut().zip(array.iter()) {
        let value = object
            .as_i64()
            .map_err(|_| Error::malformed("/ByteRange holds something that is not a number"))?;
        *slot = usize::try_from(value)
            .map_err(|_| Error::malformed("/ByteRange holds a negative offset"))?;
    }
    Ok(out)
}

fn verify_field(
    document: &Document,
    field_id: ObjectId,
    bytes: &[u8],
    options: &VerifyOptions,
) -> Result<PdfSignatureVerification> {
    let field = document
        .get_dictionary(field_id)
        .map_err(|e| Error::malformed(format!("signature field: {e}")))?;
    let signature = signature_dictionary(document, field_id)?;
    let range = read_byte_range(document, signature)?;

    let contents = signature
        .get(b"Contents")
        .ok()
        .and_then(|o| o.as_str().ok())
        .ok_or_else(|| Error::malformed("the signature has no /Contents"))?
        .to_vec();

    // Where the hex string sits in the file, brackets included. The range's gap has to be exactly
    // this; anything else means bytes were left unsigned on purpose.
    let gap_start = range[0] + range[1];
    let gap_end = range[2];
    let byte_range_sound = range[0] == 0
        && gap_end >= gap_start
        && gap_end <= bytes.len()
        && bytes.get(gap_start) == Some(&b'<')
        && bytes.get(gap_end.wrapping_sub(1)) == Some(&b'>')
        // The bytes between the brackets must all be hex, or something is hiding in there.
        && bytes[gap_start + 1..gap_end - 1]
            .iter()
            .all(|b| b.is_ascii_hexdigit());

    let covered_end = range[2] + range[3];
    let covers_whole_file = covered_end == bytes.len();
    let bytes_after = bytes.len().saturating_sub(covered_end);

    let signed_bytes = {
        let mut buffer = Vec::with_capacity(range[1] + range[3]);
        buffer.extend_from_slice(bytes.get(range[0]..range[0] + range[1]).unwrap_or(&[]));
        buffer.extend_from_slice(bytes.get(range[2]..covered_end).unwrap_or(&[]));
        buffer
    };

    let cms_der = der_structure(&contents);
    let cms_result = cms::verify_signed_data(&cms_der, &signed_bytes)?;

    let timestamp = match &cms_result.timestamp_token {
        Some(token) => {
            let anchors = options
                .timestamp_anchors
                .clone()
                .unwrap_or_else(TrustAnchors::all);
            Some(tsa::verify_token_with(
                token,
                &cms_result.signature_value,
                &anchors,
            )?)
        }
        None => None,
    };

    let reference = match &timestamp {
        Some(t) if t.verified => {
            ReferenceDate::from_timestamp(Timestamp::from_unix_seconds(t.gen_time_unix))
        }
        _ => ReferenceDate::now()?,
    };

    let accept = if options.accept_test_hierarchy {
        myna_card::certificate::roots::Accept::ProductionAndTest
    } else {
        myna_card::certificate::roots::Accept::ProductionOnly
    };

    let (certificate, trust) = match myna_card::Certificate::parse(&cms_result.signer_certificate) {
        Ok(cert) => (
            Some(CertificateInfo::read(&cert)?),
            Some(x509::check_to_root(&cert, reference, accept)?),
        ),
        Err(_) => (None, None),
    };

    Ok(PdfSignatureVerification {
        field_name: string_entry(field, b"T"),
        claimed_name: string_entry(signature, b"Name"),
        reason: string_entry(signature, b"Reason"),
        location: string_entry(signature, b"Location"),
        claimed_signing_time: string_entry(signature, b"M")
            .and_then(|m| Timestamp::parse_pdf_date(&m))
            .map(|t| t.to_rfc3339()),
        signature_verified: cms_result.signature_verified,
        document_digest_matches: cms_result.message_digest_matches,
        byte_range_sound,
        covers_whole_file,
        bytes_after,
        certificate,
        trust,
        timestamp,
        signing_certificate_bound: cms_result.signing_certificate_bound,
    })
}

fn string_entry(dictionary: &lopdf::Dictionary, key: &[u8]) -> Option<String> {
    dictionary
        .get(key)
        .ok()
        .and_then(|o| o.as_str().ok())
        .map(|b| String::from_utf8_lossy(b).into_owned())
}

/// Take exactly the DER structure out of `/Contents`, leaving the padding behind.
///
/// `/Contents` is a fixed-size run of hex reserved before the signature exists, so the structure is
/// followed by zeros. They have to go, but not by scanning back for the last non-zero byte: DER
/// content ends in `0x00` often enough — roughly one signature in every few hundred — and trimming
/// it takes a byte of the signature with it. The length is written in the DER itself; read it.
fn der_structure(contents: &[u8]) -> Vec<u8> {
    let Some(&first_length) = contents.get(1) else {
        return contents.to_vec();
    };
    let (header, length) = if first_length < 0x80 {
        (2usize, usize::from(first_length))
    } else {
        let count = usize::from(first_length & 0x7F);
        if count == 0 || count > 4 || contents.len() < 2 + count {
            return contents.to_vec();
        }
        let length = contents[2..2 + count]
            .iter()
            .fold(0usize, |acc, b| (acc << 8) | usize::from(*b));
        (2 + count, length)
    };

    match contents.get(..header + length) {
        Some(exact) => exact.to_vec(),
        // Not the shape it claims; hand it over whole and let the parser say so.
        None => contents.to_vec(),
    }
}

#[cfg(all(test, feature = "soft-signer"))]
mod tests {
    use super::*;
    use crate::pdf::sign::{PdfSignOptions, sign, tests::blank_pdf};
    use crate::signer::SoftSigner;

    fn signer() -> SoftSigner {
        SoftSigner::generate(
            "CN=PDF Signer,C=JP",
            Timestamp::from_unix_seconds(1_700_000_000),
            3650,
        )
        .unwrap()
    }

    #[test]
    fn verifies_a_signature_we_made() {
        let mut s = signer();
        let options = PdfSignOptions {
            reason: Some("承認".into()),
            location: Some("Tokyo".into()),
            ..Default::default()
        };
        let signed = sign(&mut s, &blank_pdf(), &options).unwrap();

        let results = verify(&signed.bytes, &VerifyOptions::default()).unwrap();
        assert_eq!(results.len(), 1);
        let r = &results[0];
        assert!(r.signature_verified, "{r:#?}");
        assert!(r.document_digest_matches);
        assert!(r.byte_range_sound);
        assert!(r.covers_whole_file);
        assert!(r.signing_certificate_bound);
        assert_eq!(r.reason.as_deref(), Some("承認"));
        assert_eq!(r.claimed_name.as_deref(), Some("PDF Signer"));
        assert_eq!(
            r.certificate.as_ref().unwrap().common_name.as_deref(),
            Some("PDF Signer")
        );
    }

    #[test]
    fn a_byte_changed_after_signing_is_caught() {
        let mut s = signer();
        let mut signed = sign(&mut s, &blank_pdf(), &PdfSignOptions::default())
            .unwrap()
            .bytes;

        // Flip a byte inside the signed range, well away from the signature itself.
        let range = byte_range_of(&signed).unwrap();
        signed[range[1] / 2] ^= 0x01;

        let results = verify(&signed, &VerifyOptions::default()).unwrap();
        assert!(
            !results[0].document_digest_matches,
            "a changed document must not pass"
        );
    }

    #[test]
    fn content_hidden_outside_the_byte_range_is_caught() {
        // The attack the byte range check exists for: widen the gap so that bytes between the
        // signature and the rest of the file are covered by nothing.
        let mut s = signer();
        let signed = sign(&mut s, &blank_pdf(), &PdfSignOptions::default())
            .unwrap()
            .bytes;

        let range = byte_range_of(&signed).unwrap();
        let mut forged = signed.clone();
        // Shrink the first span so a stretch before the signature falls outside the range.
        let text = format!("[0 {} {} {}]", range[1] - 64, range[2], range[3]);
        let start = find(&forged, b"/ByteRange").unwrap();
        let open = start + find(&forged[start..], b"[").unwrap();
        let close = open + find(&forged[open..], b"]").unwrap();
        forged[open..close + 1].fill(b' ');
        forged[open..open + text.len()].copy_from_slice(text.as_bytes());

        let results = verify(&forged, &VerifyOptions::default()).unwrap();
        assert!(
            !results[0].byte_range_sound,
            "a gap wider than /Contents must be reported"
        );
    }

    fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
        haystack
            .windows(needle.len())
            .position(|window| window == needle)
    }

    /// A signature whose DER happens to end in a zero byte.
    ///
    /// The padding after the structure is zeros, so "strip trailing zeros" looks like the way to
    /// find the end — until the structure's own last byte is one, and the signature loses a byte.
    /// It depends on the content, so it fails on roughly one signature in a few hundred.
    #[test]
    fn padding_is_removed_by_length_and_not_by_looking_for_zeros() {
        // A short DER SEQUENCE whose content ends in 0x00, then padding.
        let mut contents = vec![0x30, 0x03, 0x02, 0x01, 0x00];
        let structure = contents.clone();
        contents.extend(std::iter::repeat_n(0u8, 40));
        assert_eq!(der_structure(&contents), structure);

        // The long form of the length, too.
        let mut long = vec![0x30, 0x82, 0x01, 0x00];
        long.extend(std::iter::repeat_n(0xAAu8, 256));
        let structure = long.clone();
        long.extend(std::iter::repeat_n(0u8, 100));
        assert_eq!(der_structure(&long), structure);
    }

    #[test]
    fn an_unsigned_pdf_reports_no_signatures() {
        assert!(
            verify(&blank_pdf(), &VerifyOptions::default())
                .unwrap()
                .is_empty()
        );
    }
}
