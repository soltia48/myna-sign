//! What a visible signature looks like on the page.
//!
//! A signature field is drawn by the form XObject in its `/AP /N`. This module builds one holding
//! an image, which is the usual 印影 case.
//!
//! # JPEG is passed through
//!
//! PDF's `/DCTDecode` filter *is* JPEG, so a JPEG is embedded as it arrived — no decode, no
//! re-encode, no generation loss. Anything else is decoded and written as Flate-compressed
//! samples, with the alpha channel becoming an `/SMask` so a stamp with a transparent background
//! stays transparent over the page.

use lopdf::{Dictionary, Document, Object, ObjectId, Stream};

use crate::error::{Error, Result};

/// An image to draw in the signature field.
#[derive(Debug, Clone)]
pub struct SignatureImage {
    /// The file as read from disk: PNG, JPEG, or anything else `image` decodes.
    pub bytes: Vec<u8>,
    /// The size in PDF points the image is meant to be placed at, where that is known.
    ///
    /// A panel this program drew knows it — the text was laid out at a chosen size and then
    /// oversampled. A file the signer picked does not: a PNG carries pixels, not a physical size,
    /// and guessing one from a DPI tag would be guessing.
    pub natural_size: Option<(f32, f32)>,
}

impl SignatureImage {
    /// An image of unknown physical size, as read from a file.
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        SignatureImage {
            bytes,
            natural_size: None,
        }
    }
}

/// Where and how a signature appears.
#[derive(Debug, Clone)]
pub struct Appearance {
    /// Which page, counting from 1.
    pub page: usize,
    /// `[x1 y1 x2 y2]` in PDF user space — **origin at the bottom left**, unlike a canvas.
    pub rect: [f32; 4],
    /// The image. `None` draws nothing, which is a field that occupies space and shows nothing.
    pub image: Option<SignatureImage>,
}

/// Where a generated panel goes when the signer has not placed one by hand.
///
/// Bottom right of the page, inside a margin, at `height` points tall and as wide as the image's
/// proportions make it. Deriving the width rather than fixing it is what keeps the panel from
/// being letterboxed inside its own field.
pub fn default_placement(pdf: &[u8], page: usize, image: &SignatureImage) -> Result<Appearance> {
    /// Distance from the trimmed edge of the page.
    const MARGIN: f32 = 36.0;

    let media = super::media_box(pdf, page)?;
    // `/MediaBox` corners are not required to be given lower-left first.
    let (left, bottom, right) = (
        media[0].min(media[2]),
        media[1].min(media[3]),
        media[0].max(media[2]),
    );

    let (mut width, mut height) = match image.natural_size {
        Some(size) => size,
        None => {
            // Nothing says how big it should be, so pick a height and keep its proportions.
            const FALLBACK_HEIGHT: f32 = 56.0;
            let decoded = image::load_from_memory(&image.bytes).map_err(|e| {
                Error::malformed(format!("the signature image is not readable: {e}"))
            })?;
            let aspect = decoded.width() as f32 / decoded.height().max(1) as f32;
            (FALLBACK_HEIGHT * aspect, FALLBACK_HEIGHT)
        }
    };

    // Never wider than the page allows, however long the holder's name turned out to be.
    let usable = (right - left - MARGIN * 2.0).max(1.0);
    if width > usable {
        height *= usable / width;
        width = usable;
    }

    let x2 = right - MARGIN;
    let y1 = bottom + MARGIN;
    Ok(Appearance {
        page,
        rect: [x2 - width, y1, x2, y1 + height],
        image: Some(image.clone()),
    })
}

impl Appearance {
    /// The width and height of [`Appearance::rect`].
    pub fn size(&self) -> (f32, f32) {
        (
            (self.rect[2] - self.rect[0]).abs(),
            (self.rect[3] - self.rect[1]).abs(),
        )
    }

    /// Build the appearance and return the object id of its `/N` stream.
    ///
    /// # Why there are four streams and not one
    ///
    /// Adobe's signature appearances are layered: `/N` draws a form called `FRM`, which draws
    /// `n0` (the background) and `n2` (what the signer sees). Acrobat writes exactly this shape
    /// for every signature it makes, and walks it when a signature is clicked — a flat appearance
    /// with the drawing done directly in `/N` renders correctly everywhere else and makes Acrobat
    /// report an error while validating.
    ///
    /// Nothing about the signature depends on it. It is the shape Acrobat expects to find.
    pub(crate) fn build(&self, document: &mut Document) -> Result<ObjectId> {
        let (width, height) = self.size();
        if width <= 0.0 || height <= 0.0 {
            return Err(Error::malformed(
                "a visible signature needs a rectangle with a width and a height",
            ));
        }

        // n2 — what the signer sees.
        let mut resources = Dictionary::new();
        let mut content = Vec::new();
        if let Some(image) = &self.image {
            let (image_id, pixels_wide, pixels_high) = embed_image(document, image)?;
            let mut xobjects = Dictionary::new();
            xobjects.set("Im0", Object::Reference(image_id));
            resources.set("XObject", Object::Dictionary(xobjects));

            // Fit the image inside the field without distorting it, and centre what is left over.
            // Stretching it to the rectangle would squash a stamp — or a panel of text — into
            // whatever shape the rectangle happened to be dragged.
            let scale = (width / pixels_wide as f32).min(height / pixels_high as f32);
            let drawn_width = pixels_wide as f32 * scale;
            let drawn_height = pixels_high as f32 * scale;
            let left = (width - drawn_width) / 2.0;
            let bottom = (height - drawn_height) / 2.0;
            content = format!("q {drawn_width} 0 0 {drawn_height} {left} {bottom} cm /Im0 Do Q\n")
                .into_bytes();
        }
        let n2 = form(document, [0.0, 0.0, width, height], resources, content)?;

        // n0 — the background layer. Adobe writes an empty one at a fixed size.
        let n0 = form(
            document,
            [0.0, 0.0, 100.0, 100.0],
            Dictionary::new(),
            b"% DSBlank\n".to_vec(),
        )?;

        // FRM — draws the layers in order.
        let mut layers = Dictionary::new();
        layers.set("n0", Object::Reference(n0));
        layers.set("n2", Object::Reference(n2));
        let mut frm_resources = Dictionary::new();
        frm_resources.set("XObject", Object::Dictionary(layers));
        let frm = form(
            document,
            [0.0, 0.0, width, height],
            frm_resources,
            b"q 1 0 0 1 0 0 cm /n0 Do Q\nq 1 0 0 1 0 0 cm /n2 Do Q\n".to_vec(),
        )?;

        // N — what the annotation points at.
        let mut outer = Dictionary::new();
        let mut outer_xobjects = Dictionary::new();
        outer_xobjects.set("FRM", Object::Reference(frm));
        outer.set("XObject", Object::Dictionary(outer_xobjects));
        form(
            document,
            [0.0, 0.0, width, height],
            outer,
            b"/FRM Do\n".to_vec(),
        )
    }
}

/// A form XObject.
fn form(
    document: &mut Document,
    bbox: [f32; 4],
    resources: Dictionary,
    content: Vec<u8>,
) -> Result<ObjectId> {
    let mut dict = Dictionary::new();
    dict.set("Type", Object::Name(b"XObject".to_vec()));
    dict.set("Subtype", Object::Name(b"Form".to_vec()));
    dict.set(
        "BBox",
        Object::Array(bbox.iter().map(|v| Object::Real(*v)).collect()),
    );
    dict.set("Resources", Object::Dictionary(resources));
    Ok(document.add_object(Object::Stream(Stream::new(dict, content))))
}

/// Put an image in the document and return its object id and pixel size.
fn embed_image(document: &mut Document, image: &SignatureImage) -> Result<(ObjectId, u32, u32)> {
    if is_jpeg(&image.bytes) {
        return embed_jpeg(document, &image.bytes);
    }
    embed_decoded(document, &image.bytes)
}

fn is_jpeg(bytes: &[u8]) -> bool {
    bytes.starts_with(&[0xFF, 0xD8, 0xFF])
}

/// Embed a JPEG unchanged, as `/DCTDecode`.
fn embed_jpeg(document: &mut Document, bytes: &[u8]) -> Result<(ObjectId, u32, u32)> {
    let reader = image::ImageReader::new(std::io::Cursor::new(bytes))
        .with_guessed_format()
        .map_err(|e| Error::io("reading the signature image", e))?;
    let (width, height) = reader
        .into_dimensions()
        .map_err(|e| Error::malformed(format!("the signature image is not readable: {e}")))?;

    let mut dict = image_dictionary(width, height, b"DeviceRGB");
    dict.set("Filter", Object::Name(b"DCTDecode".to_vec()));
    let mut stream = Stream::new(dict, bytes.to_vec());
    // Already compressed; a second pass would only make it bigger.
    stream.set_content(bytes.to_vec());
    Ok((document.add_object(Object::Stream(stream)), width, height))
}

/// Decode anything else and write it as Flate-compressed samples, with alpha as an `/SMask`.
fn embed_decoded(document: &mut Document, bytes: &[u8]) -> Result<(ObjectId, u32, u32)> {
    let decoded = image::load_from_memory(bytes)
        .map_err(|e| Error::malformed(format!("the signature image is not readable: {e}")))?;
    let rgba = decoded.to_rgba8();
    let (width, height) = rgba.dimensions();

    let mut rgb = Vec::with_capacity((width * height * 3) as usize);
    let mut alpha = Vec::with_capacity((width * height) as usize);
    let mut opaque = true;
    for pixel in rgba.pixels() {
        rgb.extend_from_slice(&pixel.0[..3]);
        alpha.push(pixel.0[3]);
        opaque &= pixel.0[3] == 0xFF;
    }

    let mut dict = image_dictionary(width, height, b"DeviceRGB");

    if !opaque {
        let mut mask_dict = image_dictionary(width, height, b"DeviceGray");
        let mut mask = Stream::new(mask_dict.clone(), alpha);
        mask.compress()
            .map_err(|e| Error::malformed(format!("compressing the image mask failed: {e}")))?;
        mask_dict = mask.dict.clone();
        let _ = mask_dict;
        let mask_id = document.add_object(Object::Stream(mask));
        dict.set("SMask", Object::Reference(mask_id));
    }

    let mut stream = Stream::new(dict, rgb);
    stream
        .compress()
        .map_err(|e| Error::malformed(format!("compressing the signature image failed: {e}")))?;
    Ok((document.add_object(Object::Stream(stream)), width, height))
}

fn image_dictionary(width: u32, height: u32, colour_space: &[u8]) -> Dictionary {
    let mut dict = Dictionary::new();
    dict.set("Type", Object::Name(b"XObject".to_vec()));
    dict.set("Subtype", Object::Name(b"Image".to_vec()));
    dict.set("Width", Object::Integer(i64::from(width)));
    dict.set("Height", Object::Integer(i64::from(height)));
    dict.set("ColorSpace", Object::Name(colour_space.to_vec()));
    dict.set("BitsPerComponent", Object::Integer(8));
    dict
}

#[cfg(all(test, feature = "soft-signer"))]
mod tests {
    use super::*;
    use crate::pdf::sign::{PdfSignOptions, sign, tests::blank_pdf};
    use crate::pdf::verify::{VerifyOptions, verify};
    use crate::signer::SoftSigner;
    use crate::time::Timestamp;

    fn signer() -> SoftSigner {
        SoftSigner::generate(
            "CN=PDF Signer,C=JP",
            Timestamp::from_unix_seconds(1_700_000_000),
            3650,
        )
        .unwrap()
    }

    /// A small PNG with a transparent corner, encoded here rather than committed as a fixture.
    fn stamp_png() -> Vec<u8> {
        let mut buffer = image::RgbaImage::new(8, 8);
        for (x, y, pixel) in buffer.enumerate_pixels_mut() {
            let opaque = (x + y) % 2 == 0;
            *pixel = image::Rgba([200, 30, 30, if opaque { 255 } else { 0 }]);
        }
        let mut out = std::io::Cursor::new(Vec::new());
        image::DynamicImage::ImageRgba8(buffer)
            .write_to(&mut out, image::ImageFormat::Png)
            .unwrap();
        out.into_inner()
    }

    #[test]
    fn a_visible_signature_still_verifies() {
        let mut s = signer();
        let options = PdfSignOptions {
            appearance: Some(Appearance {
                page: 1,
                rect: [50.0, 50.0, 200.0, 120.0],
                image: Some(SignatureImage::from_bytes(stamp_png())),
            }),
            ..Default::default()
        };
        let signed = sign(&mut s, &blank_pdf(), &options).unwrap();

        let results = verify(&signed.bytes, &VerifyOptions::default()).unwrap();
        assert_eq!(results.len(), 1);
        assert!(results[0].signature_verified);
        assert!(results[0].document_digest_matches);
        assert!(results[0].byte_range_sound);
    }

    /// Adobe's layered appearance: `/N` draws `FRM`, which draws `n0` and `n2`.
    ///
    /// Acrobat writes this for every signature it makes and walks it when one is clicked. A flat
    /// appearance — the drawing done directly in `/N` — renders correctly in every other reader
    /// and makes Acrobat report an error while validating, which is how this was found: an
    /// invisible signature on the same document validated, a visible one did not.
    #[test]
    fn the_appearance_has_the_layers_acrobat_looks_for() {
        use crate::pdf::sign::{PdfSignOptions, sign, tests::blank_pdf};
        use lopdf::Document;

        let mut s = signer();
        let options = PdfSignOptions {
            appearance: Some(Appearance {
                page: 1,
                rect: [50.0, 50.0, 200.0, 120.0],
                image: Some(SignatureImage::from_bytes(stamp_png())),
            }),
            ..Default::default()
        };
        let signed = sign(&mut s, &blank_pdf(), &options).unwrap();
        let document = Document::load_mem(&signed.bytes).unwrap();

        let field = document
            .get_dictionary(crate::pdf::verify::signature_field_ids(&document)[0])
            .unwrap();
        let Ok(Object::Dictionary(ap)) = field.get(b"AP") else {
            panic!("no /AP");
        };
        let Ok(Object::Reference(n)) = ap.get(b"N") else {
            panic!("/AP /N is not a reference");
        };

        // Each step names the next by the name Acrobat expects.
        let named = |id: &lopdf::ObjectId, name: &[u8]| -> lopdf::ObjectId {
            let stream = document.get_object(*id).unwrap().as_stream().unwrap();
            let Ok(Object::Dictionary(resources)) = stream.dict.get(b"Resources") else {
                panic!("no /Resources");
            };
            let Ok(Object::Dictionary(xobjects)) = resources.get(b"XObject") else {
                panic!("no /XObject in /Resources");
            };
            match xobjects.get(name) {
                Ok(Object::Reference(id)) => *id,
                other => panic!("/{} is {other:?}", String::from_utf8_lossy(name)),
            }
        };

        let frm = named(n, b"FRM");
        let n0 = named(&frm, b"n0");
        let n2 = named(&frm, b"n2");

        // n2 is where the picture is; n0 is Adobe's blank background.
        assert!(document.get_object(n0).unwrap().as_stream().is_ok());
        let _ = named(&n2, b"Im0");
    }

    #[test]
    fn transparency_becomes_a_soft_mask() {
        let mut document = Document::with_version("1.7");
        let (id, _, _) = embed_decoded(&mut document, &stamp_png()).unwrap();
        let stream = document.get_object(id).unwrap().as_stream().unwrap();
        assert!(
            stream.dict.get(b"SMask").is_ok(),
            "an image with transparency needs an /SMask or the stamp gets a white box"
        );
    }

    #[test]
    fn a_rectangle_with_no_area_is_refused() {
        let mut document = Document::with_version("1.7");
        let appearance = Appearance {
            page: 1,
            rect: [10.0, 10.0, 10.0, 40.0],
            image: None,
        };
        assert!(appearance.build(&mut document).is_err());
    }

    #[test]
    fn a_page_that_does_not_exist_is_refused() {
        let mut s = signer();
        let options = PdfSignOptions {
            appearance: Some(Appearance {
                page: 9,
                rect: [0.0, 0.0, 10.0, 10.0],
                image: None,
            }),
            ..Default::default()
        };
        let e = sign(&mut s, &blank_pdf(), &options).unwrap_err();
        assert!(e.to_string().contains("no page 9"), "{e}");
    }
}
