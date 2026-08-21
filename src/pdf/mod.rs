//! PDF signatures.
//!
//! A signed PDF is the original file, byte for byte, followed by an incremental update that adds
//! a signature dictionary. `/Contents` holds a detached CMS `SignedData` over everything in the
//! file except itself, and `/ByteRange` says which bytes those are.
//!
//! # Why incremental
//!
//! [`lopdf::IncrementalDocument`] writes the previous revision out unchanged and appends. That is
//! not a convenience: a signature covers a byte range, so rewriting any earlier byte invalidates
//! every signature already in the file. Appending means a second signer can sign a document
//! without breaking the first signature, and it means the reader can show what the document looked
//! like at each signature.
//!
//! # The chicken and the egg
//!
//! `/Contents` is a signature over a file that contains `/Contents`. The way out is to write it
//! twice: once as a fixed-size run of zeros, then again with the real signature once the file's
//! bytes — and therefore its digest — are known. `/ByteRange` is patched in place, padded with
//! trailing spaces so that nothing moves. See [`sign::sign`].

pub mod appearance;
pub mod block;
pub mod sign;
pub mod verify;

use crate::error::{Error, Result};

/// How many pages a PDF has.
pub fn page_count(bytes: &[u8]) -> Result<usize> {
    let document = lopdf::Document::load_mem(bytes)
        .map_err(|e| Error::malformed(format!("not a PDF this program can read: {e}")))?;
    Ok(document.get_pages().len())
}

/// A page's `/MediaBox`, as `[x1, y1, x2, y2]` in PDF user space.
///
/// `/MediaBox` is an inheritable attribute: a page that does not carry one takes it from its
/// `/Parent`, and most documents put it on the page tree rather than on every page. Reading only
/// the page dictionary would report a default size for perfectly ordinary files.
pub fn media_box(bytes: &[u8], page: usize) -> Result<[f32; 4]> {
    let document = lopdf::Document::load_mem(bytes)
        .map_err(|e| Error::malformed(format!("not a PDF this program can read: {e}")))?;
    let pages = document.get_pages();
    let mut id = *pages
        .get(&(page as u32))
        .ok_or_else(|| Error::malformed(format!("the document has no page {page}")))?;

    // Up the tree until something states a `/MediaBox`. Bounded, so a `/Parent` loop in a
    // malformed file stops rather than hanging.
    for _ in 0..32 {
        let Ok(dictionary) = document.get_dictionary(id) else {
            break;
        };
        if let Ok(lopdf::Object::Array(items)) = dictionary.get(b"MediaBox") {
            let mut out = [0.0f32; 4];
            if items.len() != 4 {
                return Err(Error::malformed("/MediaBox does not have four entries"));
            }
            for (slot, item) in out.iter_mut().zip(items) {
                *slot = item.as_float().map_err(|_| {
                    Error::malformed("/MediaBox holds something that is not a number")
                })?;
            }
            return Ok(out);
        }
        match dictionary.get(b"Parent") {
            Ok(lopdf::Object::Reference(parent)) => id = *parent,
            _ => break,
        }
    }
    Err(Error::malformed(format!("page {page} states no /MediaBox")))
}

pub use appearance::{Appearance, SignatureImage, default_placement};
pub use block::SignatureBlock;
pub use sign::{PdfSignOptions, sign};
pub use verify::{PdfSignatureVerification, verify};
