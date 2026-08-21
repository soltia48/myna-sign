//! Adding a signature to a PDF.

use lopdf::{Dictionary, Document, IncrementalDocument, Object, ObjectId, StringFormat};

use crate::cms::{self, SignedDataParams};
use crate::error::{Error, Result};
use crate::signer::{DigestSigner, sha256};
use crate::time::Timestamp;

use super::appearance::Appearance;

/// Bytes reserved in `/Contents` for the CMS structure.
///
/// Measured rather than guessed. A signature from a card runs about 4 KB — 256 bytes of signature,
/// a 1.8 KB signing certificate, a 1.3 KB CA certificate and the attributes — and a timestamp
/// token adds up to 6 KB more; a real DigiCert token measured 5,999 bytes and a FreeTSA one 4,636.
/// 16 KiB leaves room for both with a wide margin, and the hex that goes in the file is twice this.
pub const RESERVED_BYTES: usize = 16 * 1024;

/// The default appearance a signature field carries.
///
/// Never used to draw anything — the field has an explicit `/AP` — but Acrobat writes one, and a
/// `/DA` naming a font obliges the form to have that font in its `/DR`. Both are kept consistent
/// by [`ensure_default_resources`].
const DEFAULT_APPEARANCE: &[u8] = b"/Helv 0 Tf 0 g";

/// The placeholder every `/ByteRange` entry is written as before being patched.
///
/// Ten digits, which is wider than any offset a PDF this program will meet, so the real values
/// always fit in the space reserved and the file's length never changes when they are written.
const BYTE_RANGE_PLACEHOLDER: i64 = 9_999_999_999;

/// What to record in the signature.
#[derive(Debug, Clone, Default)]
pub struct PdfSignOptions {
    /// `/Name` — who signed. Defaults to the certificate's `CN`.
    pub name: Option<String>,
    /// `/Reason` — why.
    pub reason: Option<String>,
    /// `/Location` — where.
    pub location: Option<String>,
    /// `/ContactInfo`.
    pub contact: Option<String>,
    /// The visible appearance. `None` makes an invisible signature.
    pub appearance: Option<Appearance>,
    /// The claimed signing time. Defaults to now.
    ///
    /// Written as `/M` and as the CMS `signingTime`. **Neither is evidence**: the signer chose
    /// them. A timestamp token is the part a third party attests to.
    pub signing_time: Option<Timestamp>,
    /// Certificates to carry besides the signer's — the CA above it, so a verifier can build the
    /// chain without having the card to hand.
    pub extra_certificates: Vec<Vec<u8>>,
}

/// A signed PDF, and what a caller needs to timestamp it.
#[derive(Debug, Clone)]
pub struct SignedPdf {
    /// The finished file.
    pub bytes: Vec<u8>,
    /// `signerInfo.signature` — what an RFC 3161 token is computed over.
    pub signature_value: Vec<u8>,
    /// Where the CMS sits in [`SignedPdf::bytes`], so a timestamp can be written in without
    /// signing again.
    contents_span: (usize, usize),
    /// The CMS as it stands, so a timestamp can be attached to it.
    cms_der: Vec<u8>,
}

impl SignedPdf {
    /// Attach an RFC 3161 token and rewrite `/Contents`.
    ///
    /// The signature itself does not change — the token covers it — so nothing needs re-signing
    /// and the `/ByteRange` still holds. Only the bytes inside the placeholder move.
    pub fn attach_timestamp(&mut self, token_der: &[u8]) -> Result<()> {
        let with_token = cms::attach_timestamp(&self.cms_der, token_der)?;
        write_contents(&mut self.bytes, self.contents_span, &with_token)?;
        self.cms_der = with_token;
        Ok(())
    }
}

/// Sign a PDF.
///
/// The result is `original` unchanged, followed by an incremental update carrying the signature.
pub fn sign<S: DigestSigner + ?Sized>(
    signer: &mut S,
    original: &[u8],
    options: &PdfSignOptions,
) -> Result<SignedPdf> {
    let signing_time = match options.signing_time {
        Some(t) => t,
        None => Timestamp::now()?,
    };

    let name = match &options.name {
        Some(n) => Some(n.clone()),
        None => crate::x509::CertificateInfo::read(signer.certificate())?.common_name,
    };

    let mut bytes = build_revision(original, options, signing_time, name)?;
    let contents_span = find_placeholder(&bytes)?;
    patch_byte_range(&mut bytes, contents_span)?;

    let digest = digest_byte_range(&bytes, contents_span);
    let cms_der = cms::build_signed_data(
        signer,
        &SignedDataParams {
            content_digest: digest,
            content_type: cms::ID_DATA,
            extra_certificates: &options.extra_certificates,
            signing_time,
        },
    )?;
    let signature_value = cms::verify_signed_data(&cms_der, &[])?.signature_value;

    write_contents(&mut bytes, contents_span, &cms_der)?;

    Ok(SignedPdf {
        bytes,
        signature_value,
        contents_span,
        cms_der,
    })
}

/// Build the incremental revision, with the signature still a placeholder.
fn build_revision(
    original: &[u8],
    options: &PdfSignOptions,
    signing_time: Timestamp,
    name: Option<String>,
) -> Result<Vec<u8>> {
    let previous = Document::load_mem(original).map_err(|e| {
        Error::malformed(format!("the input is not a PDF this program can read: {e}"))
    })?;
    let catalog_id = root_id(&previous)?;
    let field_name = free_field_name(&taken_field_names(&previous));
    let pages = previous.get_pages();

    let mut incremental = IncrementalDocument::create_from(original.to_vec(), previous);

    // The signature dictionary. `/Contents` is a run of zeros for now, and `/ByteRange` is written
    // at its widest so that patching it later cannot change the file's length.
    let signature_id =
        incremental
            .new_document
            .add_object(Object::Dictionary(signature_dictionary(
                options,
                signing_time,
                name,
            )));

    // The field, which is also the widget annotation that draws it.
    let (page_number, rect) = match &options.appearance {
        Some(a) => (a.page, a.rect),
        None => (1, [0.0, 0.0, 0.0, 0.0]),
    };
    let page_id = *pages
        .get(&(page_number as u32))
        .ok_or_else(|| Error::malformed(format!("the document has no page {page_number}")))?;

    let mut field = Dictionary::new();
    field.set("Type", Object::Name(b"Annot".to_vec()));
    field.set("Subtype", Object::Name(b"Widget".to_vec()));
    field.set("FT", Object::Name(b"Sig".to_vec()));
    field.set(
        "T",
        Object::String(field_name.into_bytes(), StringFormat::Literal),
    );
    field.set("V", Object::Reference(signature_id));
    field.set("P", Object::Reference(page_id));
    field.set(
        "Rect",
        Object::Array(rect.iter().map(|v| Object::Real(*v)).collect()),
    );
    // Print (4) | Locked (128): visible when printed, and not to be moved by a reader.
    field.set("F", Object::Integer(132));

    // Acrobat writes both of these on every signature widget it makes, `/MK` as an empty
    // dictionary. They are optional in the specification and no other reader has ever wanted
    // them; Acrobat asking for a dictionary that is not there is the kind of thing that surfaces
    // as "expected a dict object" rather than as anything that names the entry.
    field.set("MK", Object::Dictionary(Dictionary::new()));
    field.set(
        "DA",
        Object::String(DEFAULT_APPEARANCE.to_vec(), StringFormat::Literal),
    );

    if let Some(appearance) = &options.appearance {
        let stream_id = appearance.build(&mut incremental.new_document)?;
        let mut ap = Dictionary::new();
        ap.set("N", Object::Reference(stream_id));
        field.set("AP", Object::Dictionary(ap));
    }

    let field_id = incremental
        .new_document
        .add_object(Object::Dictionary(field));

    add_annotation(&mut incremental, page_id, field_id)?;
    update_acroform(&mut incremental, catalog_id, field_id)?;

    // The second half of `/ID` identifies the revision and is supposed to change with it; the
    // first half identifies the document and is not. Copying both unchanged, as the previous
    // trailer has them, says this revision is the one before it.
    refresh_file_identifier(&mut incremental, original);

    let mut bytes = Vec::new();
    incremental
        .save_to(&mut bytes)
        .map_err(|e| Error::io("writing the signed PDF", e))?;
    blank_injected_preamble(&mut bytes, original.len());
    // A file's last line is the end-of-file marker, and every producer ends it. `lopdf` does not.
    // Appended here, before the byte range is worked out, so the signature covers it.
    bytes.push(b'\n');
    Ok(bytes)
}

/// Give the appended revision its own second `/ID`.
///
/// Derived from what is being signed, so the same input still produces the same file — the point
/// is that it differs from the *previous* revision, not that it is unpredictable.
fn refresh_file_identifier(incremental: &mut IncrementalDocument, original: &[u8]) {
    let Ok(Object::Array(existing)) = incremental.new_document.trailer.get(b"ID") else {
        return;
    };
    let Some(permanent) = existing.first().cloned() else {
        return;
    };
    let changing = Object::String(sha256(original)[..16].to_vec(), StringFormat::Hexadecimal);
    incremental
        .new_document
        .trailer
        .set("ID", Object::Array(vec![permanent, changing]));
}

/// Blank out the header `lopdf` writes at the start of the appended revision.
///
/// A PDF has one header, at byte zero. `lopdf` starts each appended revision with another one plus
/// a binary marker comment; no other producer does, and Adobe's readers treat `%PDF-` as the point
/// everything is measured from. An incremental update from Acrobat or from pyhanko goes straight
/// from the previous `%%EOF` to the first object.
///
/// The bytes are *overwritten with whitespace*, not removed: the cross-reference table has already
/// been written with absolute offsets, and shortening the file would invalidate every one of them.
/// Whitespace between revisions is ordinary and says nothing at all, which a comment cannot claim.
fn blank_injected_preamble(bytes: &mut [u8], appended_at: usize) {
    // Everything from the end of the previous revision up to the first object of this one.
    let Some(first_object) = find(&bytes[appended_at..], b" 0 obj") else {
        return;
    };
    // Back up over the object number to the start of its line.
    let mut start = appended_at + first_object;
    while start > appended_at && bytes[start - 1] != b'\n' {
        start -= 1;
    }

    let preamble = &mut bytes[appended_at..start];
    // Only touch what `lopdf` put there: a header line and a binary marker comment.
    if !preamble.contains(&b'%') {
        return;
    }
    for byte in preamble.iter_mut() {
        if *byte != b'\n' {
            *byte = b' ';
        }
    }
}

fn signature_dictionary(
    options: &PdfSignOptions,
    signing_time: Timestamp,
    name: Option<String>,
) -> Dictionary {
    let mut dict = Dictionary::new();
    dict.set("Type", Object::Name(b"Sig".to_vec()));
    dict.set("Filter", Object::Name(b"Adobe.PPKLite".to_vec()));
    dict.set("SubFilter", Object::Name(b"adbe.pkcs7.detached".to_vec()));
    dict.set(
        "ByteRange",
        Object::Array(vec![
            Object::Integer(0),
            Object::Integer(BYTE_RANGE_PLACEHOLDER),
            Object::Integer(BYTE_RANGE_PLACEHOLDER),
            Object::Integer(BYTE_RANGE_PLACEHOLDER),
        ]),
    );
    dict.set(
        "Contents",
        Object::String(vec![0u8; RESERVED_BYTES], StringFormat::Hexadecimal),
    );
    dict.set(
        "M",
        Object::String(
            signing_time.to_pdf_date().into_bytes(),
            StringFormat::Literal,
        ),
    );
    for (key, value) in [
        ("Name", name.as_ref()),
        ("Reason", options.reason.as_ref()),
        ("Location", options.location.as_ref()),
        ("ContactInfo", options.contact.as_ref()),
    ] {
        if let Some(value) = value {
            dict.set(
                key,
                Object::String(value.clone().into_bytes(), StringFormat::Literal),
            );
        }
    }
    dict
}

fn root_id(document: &Document) -> Result<ObjectId> {
    match document.trailer.get(b"Root") {
        Ok(Object::Reference(id)) => Ok(*id),
        _ => Err(Error::malformed("the PDF trailer has no /Root reference")),
    }
}

/// The elements of an array that may be written in place or reached through a reference.
///
/// PDF lets either, and producers use both. Treating a reference as if it were the array is how a
/// page ends up with `/Annots [ <the old array> , <the new widget> ]` — an array nested where a
/// viewer expects an annotation dictionary, which Acrobat reports as "expected a dict object".
fn array_elements(document: &Document, value: Option<&Object>) -> Vec<Object> {
    match value {
        Some(Object::Array(items)) => items.clone(),
        Some(Object::Reference(id)) => match document.get_object(*id) {
            Ok(Object::Array(items)) => items.clone(),
            _ => Vec::new(),
        },
        _ => Vec::new(),
    }
}

/// Append to an array belonging to `owner`, whichever way it is written.
///
/// When the array is a separate object, that object is brought forward and extended, and `owner`
/// is left alone — fewer objects rewritten, and the reference in the file keeps pointing where it
/// did. When it is written into `owner`, `owner` is brought forward instead.
fn append_to_array(
    incremental: &mut IncrementalDocument,
    owner: ObjectId,
    key: &[u8],
    value: Object,
) -> Result<()> {
    let held = incremental
        .get_prev_documents()
        .get_dictionary(owner)
        .ok()
        .and_then(|dictionary| dictionary.get(key).ok())
        .cloned();

    if let Some(Object::Reference(array_id)) = held {
        let mut elements = array_elements(
            incremental.get_prev_documents(),
            incremental.get_prev_documents().get_object(array_id).ok(),
        );
        elements.push(value);
        incremental
            .opt_clone_object_to_new_document(array_id)
            .map_err(|e| Error::malformed(format!("cannot bring the array forward: {e}")))?;
        *incremental
            .new_document
            .get_object_mut(array_id)
            .map_err(|e| Error::malformed(format!("array {array_id:?}: {e}")))? =
            Object::Array(elements);
        return Ok(());
    }

    let mut elements = array_elements(incremental.get_prev_documents(), held.as_ref());
    elements.push(value);
    incremental
        .opt_clone_object_to_new_document(owner)
        .map_err(|e| Error::malformed(format!("cannot bring {owner:?} forward: {e}")))?;
    incremental
        .new_document
        .get_object_mut(owner)
        .and_then(|o| o.as_dict_mut())
        .map_err(|e| Error::malformed(format!("{owner:?} is not a dictionary: {e}")))?
        .set(key.to_vec(), Object::Array(elements));
    Ok(())
}

/// Every form field name already in use, so a new one does not collide.
///
/// Two fields sharing a `/T` are the same field as far as a viewer is concerned, which would make
/// the new signature look like a second widget of an existing one.
fn taken_field_names(document: &Document) -> Vec<String> {
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
    array_elements(document, acroform.get(b"Fields").ok())
        .iter()
        .filter_map(|field| match field {
            Object::Reference(id) => document.get_dictionary(*id).ok(),
            Object::Dictionary(d) => Some(d),
            _ => None,
        })
        .filter_map(|field| field.get(b"T").ok().and_then(|t| t.as_str().ok()))
        .map(|name| String::from_utf8_lossy(name).into_owned())
        .collect()
}

fn resolve_dictionary<'a>(document: &'a Document, object: &'a Object) -> Option<&'a Dictionary> {
    match object {
        Object::Dictionary(d) => Some(d),
        Object::Reference(id) => document.get_dictionary(*id).ok(),
        _ => None,
    }
}

/// The first `SignatureN` nobody is using.
fn free_field_name(taken: &[String]) -> String {
    (1..)
        .map(|n| format!("Signature{n}"))
        .find(|name| !taken.iter().any(|used| used == name))
        .expect("the range is unbounded")
}

/// Add the widget to the page's `/Annots`.
fn add_annotation(
    incremental: &mut IncrementalDocument,
    page_id: ObjectId,
    field_id: ObjectId,
) -> Result<()> {
    append_to_array(incremental, page_id, b"Annots", Object::Reference(field_id))
}

/// Put the field in `/AcroForm /Fields`, keeping everything else the form says.
///
/// An `/AcroForm` carries more than a field list: `/DR` holds the resources a viewer needs to draw
/// the other fields, `/DA` their default appearance, `/NeedAppearances` whether it must. Replacing
/// the dictionary with a fresh one throws all of that away, and the form stops rendering in
/// Acrobat — so the existing one is extended rather than rebuilt.
fn update_acroform(
    incremental: &mut IncrementalDocument,
    catalog_id: ObjectId,
    field_id: ObjectId,
) -> Result<()> {
    let held = incremental
        .get_prev_documents()
        .get_dictionary(catalog_id)
        .ok()
        .and_then(|catalog| catalog.get(b"AcroForm").ok())
        .cloned();

    // Already its own object: extend it and leave the catalog alone.
    if let Some(Object::Reference(acroform_id)) = held {
        append_to_array(
            incremental,
            acroform_id,
            b"Fields",
            Object::Reference(field_id),
        )?;
        let flags = signature_flags(incremental.get_prev_documents(), acroform_id);

        let mut acroform = incremental
            .new_document
            .get_object(acroform_id)
            .and_then(|o| o.as_dict())
            .map_err(|e| Error::malformed(format!("the AcroForm is not a dictionary: {e}")))?
            .clone();
        acroform.set("SigFlags", Object::Integer(flags));
        ensure_default_resources(incremental, &mut acroform)?;
        incremental
            .new_document
            .set_object(acroform_id, Object::Dictionary(acroform));
        return Ok(());
    }

    // Written into the catalog, or not there at all.
    let previous = incremental.get_prev_documents();
    let mut acroform = match &held {
        Some(Object::Dictionary(existing)) => existing.clone(),
        _ => Dictionary::new(),
    };
    let mut fields = array_elements(previous, acroform.get(b"Fields").ok());
    fields.push(Object::Reference(field_id));
    let flags = acroform
        .get(b"SigFlags")
        .ok()
        .and_then(|o| o.as_i64().ok())
        .unwrap_or(0)
        // 1 SignaturesExist | 2 AppendOnly: the reader must not rewrite the file in place.
        | 3;
    acroform.set("Fields", Object::Array(fields));
    acroform.set("SigFlags", Object::Integer(flags));
    ensure_default_resources(incremental, &mut acroform)?;

    // Given its own object rather than written into the catalog. Both are legal, but every
    // producer that Acrobat is happy with makes it indirect, and a form dictionary is something
    // readers expect to be able to reach — and update — on its own.
    let acroform_id = incremental
        .new_document
        .add_object(Object::Dictionary(acroform));

    incremental
        .opt_clone_object_to_new_document(catalog_id)
        .map_err(|e| Error::malformed(format!("cannot bring the catalog forward: {e}")))?;
    incremental
        .new_document
        .get_object_mut(catalog_id)
        .and_then(|o| o.as_dict_mut())
        .map_err(|e| Error::malformed(format!("the catalog is not a dictionary: {e}")))?
        .set("AcroForm", Object::Reference(acroform_id));
    Ok(())
}

/// Make sure the form names a default appearance and carries the font it names.
///
/// A `/DA` of `/Helv 0 Tf 0 g` is meaningless unless `/DR /Font /Helv` resolves, and a reader that
/// follows the one to the other and finds nothing is a reader about to complain. Existing entries
/// are left exactly as they are: a form that already has a `/DA` has one for a reason.
fn ensure_default_resources(
    incremental: &mut IncrementalDocument,
    acroform: &mut Dictionary,
) -> Result<()> {
    if acroform.get(b"DA").is_err() {
        acroform.set(
            "DA",
            Object::String(DEFAULT_APPEARANCE.to_vec(), StringFormat::Literal),
        );
    }

    let mut resources = match acroform.get(b"DR") {
        Ok(Object::Dictionary(existing)) => existing.clone(),
        Ok(Object::Reference(id)) => incremental
            .get_prev_documents()
            .get_dictionary(*id)
            .cloned()
            .unwrap_or_default(),
        _ => Dictionary::new(),
    };

    let mut fonts = match resources.get(b"Font") {
        Ok(Object::Dictionary(existing)) => existing.clone(),
        Ok(Object::Reference(id)) => incremental
            .get_prev_documents()
            .get_dictionary(*id)
            .cloned()
            .unwrap_or_default(),
        _ => Dictionary::new(),
    };

    if fonts.get(b"Helv").is_err() {
        let mut helvetica = Dictionary::new();
        helvetica.set("Type", Object::Name(b"Font".to_vec()));
        helvetica.set("Subtype", Object::Name(b"Type1".to_vec()));
        helvetica.set("BaseFont", Object::Name(b"Helvetica".to_vec()));
        helvetica.set("Encoding", Object::Name(b"WinAnsiEncoding".to_vec()));
        let font_id = incremental
            .new_document
            .add_object(Object::Dictionary(helvetica));
        fonts.set("Helv", Object::Reference(font_id));
    }

    resources.set("Font", Object::Dictionary(fonts));
    acroform.set("DR", Object::Dictionary(resources));
    Ok(())
}

fn signature_flags(document: &Document, acroform_id: ObjectId) -> i64 {
    document
        .get_dictionary(acroform_id)
        .ok()
        .and_then(|d| d.get(b"SigFlags").ok())
        .and_then(|o| o.as_i64().ok())
        .unwrap_or(0)
        | 3
}

// --- The second pass ---------------------------------------------------------------------------

/// Find the `/Contents` placeholder: the offsets of `<` and one past `>`.
///
/// Searched for as the exact run of zeros that was written, which cannot occur by accident in a
/// document this program just produced.
fn find_placeholder(bytes: &[u8]) -> Result<(usize, usize)> {
    let mut needle = Vec::with_capacity(RESERVED_BYTES * 2 + 2);
    needle.push(b'<');
    needle.extend(std::iter::repeat_n(b'0', RESERVED_BYTES * 2));
    needle.push(b'>');

    find(bytes, &needle)
        .map(|start| (start, start + needle.len()))
        .ok_or_else(|| Error::malformed("the signature placeholder is not in the output"))
}

/// Replace the `/ByteRange` placeholder with the real spans, padded so the length does not change.
///
/// Whitespace inside a PDF array is free, so the difference between `9999999999` and `840` is made
/// up with trailing spaces. Nothing after this point moves, which is what lets the digest be taken
/// straight afterwards.
fn patch_byte_range(
    bytes: &mut [u8],
    (contents_start, contents_end): (usize, usize),
) -> Result<()> {
    // The *last* `/ByteRange` before the placeholder, not the first in the file. Signing an
    // already-signed document means earlier signatures' byte ranges are sitting in the bytes ahead
    // of ours, and patching one of those would corrupt a signature that was previously fine.
    let key = rfind(&bytes[..contents_start], b"/ByteRange")
        .ok_or_else(|| Error::malformed("no /ByteRange precedes the signature placeholder"))?;
    let open = key
        + find(&bytes[key..contents_start], b"[")
            .ok_or_else(|| Error::malformed("/ByteRange is not followed by an array"))?;
    let close = open
        + find(&bytes[open..contents_start], b"]")
            .ok_or_else(|| Error::malformed("/ByteRange array is not closed"))?;
    let width = close - open + 1;

    let range = format!(
        "[0 {} {} {}]",
        contents_start,
        contents_end,
        bytes.len() - contents_end
    );
    if range.len() > width {
        return Err(Error::malformed(format!(
            "the real /ByteRange needs {} bytes but only {width} were reserved",
            range.len()
        )));
    }

    bytes[open..close + 1].fill(b' ');
    bytes[open..open + range.len()].copy_from_slice(range.as_bytes());
    Ok(())
}

/// SHA-256 over the two spans the `/ByteRange` covers.
fn digest_byte_range(bytes: &[u8], (contents_start, contents_end): (usize, usize)) -> [u8; 32] {
    use sha2::Digest as _;
    let mut hasher = sha2::Sha256::new();
    hasher.update(&bytes[..contents_start]);
    hasher.update(&bytes[contents_end..]);
    hasher.finalize().into()
}

/// Write the CMS into the placeholder as hex, leaving the rest zeroed.
fn write_contents(
    bytes: &mut [u8],
    (contents_start, contents_end): (usize, usize),
    der: &[u8],
) -> Result<()> {
    // Inside the angle brackets.
    let room = contents_end - contents_start - 2;
    if der.len() * 2 > room {
        return Err(Error::malformed(format!(
            "the signature needs {} bytes but {} were reserved; \
             raise myna_sign::pdf::sign::RESERVED_BYTES",
            der.len(),
            room / 2
        )));
    }
    let hex = hex::encode_upper(der);
    let start = contents_start + 1;
    bytes[start..start + hex.len()].copy_from_slice(hex.as_bytes());
    bytes[start + hex.len()..contents_end - 1].fill(b'0');
    Ok(())
}

/// First occurrence of `needle` in `haystack`.
fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// Last occurrence of `needle` in `haystack`.
fn rfind(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .rposition(|window| window == needle)
}

/// SHA-256 of a document, for showing the user what they are about to sign.
pub fn document_digest(bytes: &[u8]) -> [u8; 32] {
    sha256(bytes)
}

#[cfg(all(test, feature = "soft-signer"))]
pub(crate) mod tests {
    use super::*;
    use crate::signer::SoftSigner;

    fn signer() -> SoftSigner {
        SoftSigner::generate(
            "CN=PDF Signer,C=JP",
            Timestamp::from_unix_seconds(1_700_000_000),
            3650,
        )
        .unwrap()
    }

    /// A one page PDF with nothing on it.
    pub(crate) fn blank_pdf() -> Vec<u8> {
        use lopdf::dictionary;
        let mut doc = Document::with_version("1.7");
        let pages_id = doc.new_object_id();
        let page_id = doc.add_object(dictionary! {
            "Type" => "Page",
            "Parent" => pages_id,
            "MediaBox" => vec![0.into(), 0.into(), 595.into(), 842.into()],
        });
        doc.objects.insert(
            pages_id,
            Object::Dictionary(dictionary! {
                "Type" => "Pages",
                "Kids" => vec![page_id.into()],
                "Count" => 1,
            }),
        );
        let catalog_id = doc.add_object(dictionary! {
            "Type" => "Catalog",
            "Pages" => pages_id,
        });
        doc.trailer.set("Root", catalog_id);
        let mut bytes = Vec::new();
        doc.save_to(&mut bytes).unwrap();
        bytes
    }

    /// A document shaped the way real producers write them: `/Annots` is a separate object, the
    /// `/AcroForm` is too, and it carries the resources the other fields are drawn with.
    pub(crate) fn form_pdf() -> Vec<u8> {
        let objects: [(u32, &[u8]); 8] = [
            (1, b"<</Type/Catalog/Pages 2 0 R/AcroForm 8 0 R>>"),
            (
                2,
                b"<</Type/Pages/Kids[3 0 R]/Count 1/MediaBox[0 0 595 842]>>",
            ),
            (3, b"<</Type/Page/Parent 2 0 R/Annots 6 0 R>>"),
            (
                4,
                b"<</Type/Annot/Subtype/Widget/FT/Tx/T(Signature1)/Rect[50 700 300 730]>>",
            ),
            (5, b"<</Type/Annot/Subtype/Square/Rect[50 600 200 650]>>"),
            (6, b"[4 0 R 5 0 R]"),
            (7, b"<</Type/Font/Subtype/Type1/BaseFont/Helvetica>>"),
            (
                8,
                b"<</Fields[4 0 R]/DR<</Font<</Helv 7 0 R>>>>/DA(/Helv 0 Tf 0 g)>>",
            ),
        ];

        let mut pdf = b"%PDF-1.7\n".to_vec();
        let mut offsets = Vec::new();
        for (id, body) in objects {
            offsets.push(pdf.len());
            pdf.extend_from_slice(format!("{id} 0 obj").as_bytes());
            pdf.extend_from_slice(body);
            pdf.extend_from_slice(b"endobj\n");
        }
        let start = pdf.len();
        pdf.extend_from_slice(
            format!("xref\n0 {}\n0000000000 65535 f \n", objects.len() + 1).as_bytes(),
        );
        for offset in offsets {
            pdf.extend_from_slice(format!("{offset:010} 00000 n \n").as_bytes());
        }
        pdf.extend_from_slice(
            format!(
                "trailer<</Size {}/Root 1 0 R>>\nstartxref\n{start}\n%%EOF",
                objects.len() + 1
            )
            .as_bytes(),
        );
        pdf
    }

    /// The bug Acrobat reported as "expected a dict object".
    ///
    /// `/Annots` is often a separate object. Putting a reference to *that array* into the page's
    /// annotation list nests an array where every entry has to be an annotation dictionary, and a
    /// viewer walking the annotations to find the one that was clicked hits it.
    #[test]
    fn an_annotation_list_holds_only_annotations() {
        let mut s = signer();
        let signed = sign(&mut s, &form_pdf(), &PdfSignOptions::default()).unwrap();
        let document = Document::load_mem(&signed.bytes).unwrap();

        let page_id = *document.get_pages().get(&1).unwrap();
        let annots = document
            .get_dictionary(page_id)
            .unwrap()
            .get(b"Annots")
            .unwrap();
        let ids: Vec<_> = match annots {
            Object::Reference(id) => match document.get_object(*id).unwrap() {
                Object::Array(items) => items.clone(),
                other => panic!("/Annots points at {other:?}, not an array"),
            },
            Object::Array(items) => items.clone(),
            other => panic!("/Annots is {other:?}"),
        };

        assert_eq!(ids.len(), 3, "the two original annotations must survive");
        for entry in &ids {
            let Object::Reference(id) = entry else {
                panic!("/Annots holds {entry:?}, which is not a reference to an annotation");
            };
            document
                .get_dictionary(*id)
                .unwrap_or_else(|_| panic!("/Annots entry {id:?} is not a dictionary"));
        }
    }

    /// An `/AcroForm` carries what the viewer needs to draw the *other* fields.
    #[test]
    fn the_existing_form_is_extended_rather_than_replaced() {
        let mut s = signer();
        let signed = sign(&mut s, &form_pdf(), &PdfSignOptions::default()).unwrap();
        let document = Document::load_mem(&signed.bytes).unwrap();

        let catalog = document.catalog().unwrap();
        let acroform = match catalog.get(b"AcroForm").unwrap() {
            Object::Reference(id) => document.get_dictionary(*id).unwrap(),
            Object::Dictionary(d) => d,
            other => panic!("/AcroForm is {other:?}"),
        };

        assert!(
            acroform.get(b"DR").is_ok(),
            "/DR was dropped; the form's other fields stop rendering"
        );
        assert!(acroform.get(b"DA").is_ok(), "/DA was dropped");
        assert_eq!(acroform.get(b"SigFlags").unwrap().as_i64().unwrap(), 3);

        let fields = match acroform.get(b"Fields").unwrap() {
            Object::Reference(id) => match document.get_object(*id).unwrap() {
                Object::Array(items) => items.clone(),
                other => panic!("/Fields points at {other:?}"),
            },
            Object::Array(items) => items.clone(),
            other => panic!("/Fields is {other:?}"),
        };
        assert_eq!(fields.len(), 2, "the existing text field must survive");
    }

    /// The fixture already has a field called `Signature1`.
    #[test]
    fn a_new_field_does_not_take_a_name_that_is_in_use() {
        let mut s = signer();
        let signed = sign(&mut s, &form_pdf(), &PdfSignOptions::default()).unwrap();
        let results = super::super::verify::verify(&signed.bytes, &Default::default()).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(
            results[0].field_name.as_deref(),
            Some("Signature2"),
            "the name collides with the text field already in the form"
        );
    }

    /// A PDF has one header. A second one part-way through the file is what a reader that
    /// measures offsets from `%PDF-` would take as the start of the document.
    #[test]
    fn the_appended_revision_does_not_start_a_second_pdf() {
        let original = blank_pdf();
        let mut s = signer();
        let signed = sign(&mut s, &original, &PdfSignOptions::default()).unwrap();

        assert!(
            signed.bytes.starts_with(b"%PDF-"),
            "the real header is at byte 0"
        );
        assert_eq!(
            find(&signed.bytes[5..], b"%PDF-"),
            None,
            "there is a second %PDF- header in the file"
        );
    }

    /// The entries Acrobat writes on every signature widget it makes.
    ///
    /// All optional by the specification, and no other reader has ever asked for them. They are
    /// here because a real Acrobat-produced signature was compared against ours entry by entry,
    /// and these were the difference.
    #[test]
    fn the_widget_carries_what_acrobat_writes() {
        let mut s = signer();
        let signed = sign(&mut s, &blank_pdf(), &PdfSignOptions::default()).unwrap();
        let document = Document::load_mem(&signed.bytes).unwrap();

        let field_id = super::super::verify::signature_field_ids(&document)[0];
        let field = document.get_dictionary(field_id).unwrap();

        assert!(
            matches!(field.get(b"MK"), Ok(Object::Dictionary(_))),
            "/MK must be a dictionary, even an empty one"
        );
        assert!(field.get(b"DA").is_ok(), "/MK's companion /DA is missing");

        // A `/DA` naming a font is a promise that the form carries it.
        let catalog = document.catalog().unwrap();
        let acroform = match catalog.get(b"AcroForm").unwrap() {
            Object::Reference(id) => document.get_dictionary(*id).unwrap(),
            Object::Dictionary(d) => d,
            other => panic!("/AcroForm is {other:?}"),
        };
        let resources = match acroform.get(b"DR").unwrap() {
            Object::Reference(id) => document.get_dictionary(*id).unwrap(),
            Object::Dictionary(d) => d,
            other => panic!("/DR is {other:?}"),
        };
        let fonts = match resources.get(b"Font").unwrap() {
            Object::Reference(id) => document.get_dictionary(*id).unwrap(),
            Object::Dictionary(d) => d,
            other => panic!("/Font is {other:?}"),
        };
        let Ok(Object::Reference(helv)) = fonts.get(b"Helv") else {
            panic!("/DA names /Helv but /DR does not carry it");
        };
        assert!(document.get_dictionary(*helv).is_ok());
    }

    /// `/AcroForm` given its own object, as every producer Acrobat is happy with does.
    #[test]
    fn the_form_is_its_own_object() {
        let mut s = signer();
        let signed = sign(&mut s, &blank_pdf(), &PdfSignOptions::default()).unwrap();
        let document = Document::load_mem(&signed.bytes).unwrap();
        assert!(
            matches!(
                document.catalog().unwrap().get(b"AcroForm"),
                Ok(Object::Reference(_))
            ),
            "/AcroForm should be reachable on its own"
        );
    }

    #[test]
    fn the_original_bytes_are_still_there_untouched() {
        // The whole point of an incremental update. If this fails, every signature already in the
        // file is broken by ours.
        let original = blank_pdf();
        let mut s = signer();
        let signed = sign(&mut s, &original, &PdfSignOptions::default()).unwrap();
        assert!(signed.bytes.len() > original.len());
        assert_eq!(&signed.bytes[..original.len()], &original[..]);
    }

    #[test]
    fn the_byte_range_covers_everything_except_the_signature() {
        let original = blank_pdf();
        let mut s = signer();
        let signed = sign(&mut s, &original, &PdfSignOptions::default()).unwrap();

        let ranges = super::super::verify::byte_range_of(&signed.bytes).unwrap();
        assert_eq!(ranges[0], 0, "must start at the first byte");
        assert_eq!(
            ranges[2] + ranges[3],
            signed.bytes.len(),
            "must reach the end of the file"
        );
        // The gap is exactly the hex string, brackets included.
        assert_eq!(signed.bytes[ranges[1]], b'<');
        assert_eq!(signed.bytes[ranges[2] - 1], b'>');
    }

    #[test]
    fn the_placeholder_is_large_enough_with_room_to_spare() {
        let mut s = signer();
        let signed = sign(&mut s, &blank_pdf(), &PdfSignOptions::default()).unwrap();
        let used = signed.cms_der.len();
        assert!(
            used < RESERVED_BYTES / 2,
            "a bare signature already uses {used} of {RESERVED_BYTES} reserved bytes, \
             leaving too little for a timestamp"
        );
    }

    #[test]
    fn signing_twice_keeps_the_first_signature_intact() {
        let original = blank_pdf();
        let mut s = signer();
        let once = sign(&mut s, &original, &PdfSignOptions::default()).unwrap();
        let twice = sign(&mut s, &once.bytes, &PdfSignOptions::default()).unwrap();

        assert_eq!(&twice.bytes[..once.bytes.len()], &once.bytes[..]);
        let results = super::super::verify::verify(&twice.bytes, &Default::default()).unwrap();
        assert_eq!(results.len(), 2, "both signatures should be found");
        assert!(results.iter().all(|r| r.signature_verified), "{results:#?}");
        // The earlier one no longer covers the whole file, and that has to be visible.
        assert!(results[0].covers_whole_file != results[1].covers_whole_file);
    }
}
