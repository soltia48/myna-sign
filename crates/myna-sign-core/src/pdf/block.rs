//! Drawing the signature block that appears on the page.
//!
//! When the signer supplies no image of their own, the field would otherwise be invisible. This
//! draws a small panel instead — who signed, when, and why — in the shape Acrobat and most
//! Japanese e-signature products use.
//!
//! # It is a picture, not evidence
//!
//! Nothing here is checked by anything. The name in the panel is drawn from the certificate, and
//! the certificate is what a verifier actually reads; the panel is for the person looking at the
//! page. A document whose panel says one thing and whose signature says another is caught by
//! [`crate::pdf::verify()`], which does not look at the panel at all. That is worth stating because
//! a drawn "電子署名" is exactly the kind of thing that gets mistaken for a verdict.
//!
//! # The font is carried, not borrowed
//!
//! A Japanese font is compiled in. Taking one from the system would make the same signature look
//! different on different machines, and would fail outright on a minimal Linux install with no CJK
//! font at all — for a picture that goes into a signed document, neither is acceptable.

use ab_glyph::{Font as _, FontRef, PxScale, ScaleFont, point};
use image::{Rgba, RgbaImage};

use crate::error::{Error, Result};
use crate::time::Timestamp;
use crate::x509::CertificateInfo;

use super::appearance::SignatureImage;

/// Noto Sans JP, subsetted to Japanese, under the SIL Open Font License 1.1.
///
/// The licence travels with it in `fonts/LICENSE-NotoSansJP.txt` and must be reproduced in any
/// distribution of this program.
const FONT: &[u8] = include_bytes!("../../fonts/NotoSansJP-Regular.otf");

/// Rendered at three times the size it is placed at, so the panel stays sharp when the page is
/// zoomed in a viewer.
const OVERSAMPLE: f32 = 3.0;

const TITLE_SIZE: f32 = 13.0 * OVERSAMPLE;
const TEXT_SIZE: f32 = 11.0 * OVERSAMPLE;
const PADDING: f32 = 9.0 * OVERSAMPLE;
/// Between the heading and the first row. Rows are spaced by their own leading.
const TITLE_GAP: f32 = 4.0 * OVERSAMPLE;
const LABEL_GAP: f32 = 8.0 * OVERSAMPLE;
const BORDER: f32 = 1.5 * OVERSAMPLE;
/// Baseline to baseline, as a multiple of the text size. Tight enough that a panel with five rows
/// is still wider than it is tall, which is the shape a signature field is usually dragged into.
const LEADING: f32 = 1.5;

const INK: Rgba<u8> = Rgba([0x14, 0x18, 0x1D, 0xFF]);
const MUTED: Rgba<u8> = Rgba([0x5B, 0x66, 0x72, 0xFF]);
const FRAME: Rgba<u8> = Rgba([0x1F, 0x5F, 0xA9, 0xFF]);
const PAPER: Rgba<u8> = Rgba([0xFF, 0xFF, 0xFF, 0xFF]);

/// What the panel says.
#[derive(Debug, Clone)]
pub struct SignatureBlock {
    /// The heading.
    pub title: String,
    /// Label and value, one per line.
    pub rows: Vec<(String, String)>,
}

impl Default for SignatureBlock {
    fn default() -> Self {
        SignatureBlock {
            title: "電子署名".into(),
            rows: Vec::new(),
        }
    }
}

impl SignatureBlock {
    /// The panel for a signature about to be made.
    ///
    /// The name comes from the certificate's 氏名 where there is one — the 署名用証明書 carries it
    /// — and falls back to the subject's `CN`.
    ///
    /// The time is the *claimed* signing time, which is the only one available while the signature
    /// is being made: a timestamp token does not exist until afterwards. It is labelled 日時 rather
    /// than anything that suggests it was attested.
    pub fn describe(
        certificate: &CertificateInfo,
        at: Timestamp,
        reason: Option<&str>,
        location: Option<&str>,
    ) -> Self {
        let name = certificate
            .holder
            .name
            .clone()
            .or_else(|| certificate.common_name.clone())
            .unwrap_or_else(|| certificate.subject.clone());

        // Shown in Japan Standard Time: the panel is drawn for a Japanese document and read by a
        // person, not parsed. The instant that is machine-readable stays UTC — the PDF's `/M`, the
        // CMS `signingTime`, and any timestamp token.
        let mut rows = vec![
            ("署名者".into(), name),
            ("日時".into(), at.to_jst_minutes()),
        ];
        if let Some(reason) = reason.filter(|r| !r.trim().is_empty()) {
            rows.push(("理由".into(), reason.to_owned()));
        }
        if let Some(location) = location.filter(|l| !l.trim().is_empty()) {
            rows.push(("場所".into(), location.to_owned()));
        }
        // Enough of the fingerprint to check against the verification screen by eye, not so much
        // that it sets the width of the whole panel.
        rows.push((
            "証明書".into(),
            certificate.fingerprint.chars().take(8).collect(),
        ));

        SignatureBlock {
            title: "電子署名".into(),
            ..Default::default()
        }
        .with_rows(rows)
    }

    fn with_rows(mut self, rows: Vec<(String, String)>) -> Self {
        self.rows = rows;
        self
    }

    /// Draw it.
    ///
    /// The result is a PNG whose proportions follow the text, so the caller does not have to guess
    /// a shape; the appearance stream fits it into whatever rectangle was chosen without
    /// distorting it.
    pub fn render(&self) -> Result<SignatureImage> {
        let font = FontRef::try_from_slice(FONT)
            .map_err(|e| Error::malformed(format!("the bundled font will not load: {e}")))?;
        let title_font = font.as_scaled(PxScale::from(TITLE_SIZE));
        let text_font = font.as_scaled(PxScale::from(TEXT_SIZE));

        let label_width = self
            .rows
            .iter()
            .map(|(label, _)| width_of(&text_font, label))
            .fold(0.0f32, f32::max);
        let value_width = self
            .rows
            .iter()
            .map(|(_, value)| width_of(&text_font, value))
            .fold(0.0f32, f32::max);

        let title_height = TITLE_SIZE * 1.2;
        let line_height = TEXT_SIZE * LEADING;

        let content_width =
            (label_width + LABEL_GAP + value_width).max(width_of(&title_font, &self.title));
        let content_height = title_height + TITLE_GAP + self.rows.len() as f32 * line_height;

        let width = (content_width + PADDING * 2.0).ceil().max(1.0) as u32;
        let height = (content_height + PADDING * 2.0).ceil().max(1.0) as u32;

        let mut canvas = RgbaImage::from_pixel(width, height, PAPER);
        draw_frame(&mut canvas, FRAME);

        let mut baseline = PADDING + TITLE_SIZE;
        draw_text(
            &mut canvas,
            &title_font,
            &self.title,
            PADDING,
            baseline,
            FRAME,
        );
        baseline += TITLE_GAP + line_height;

        for (label, value) in &self.rows {
            draw_text(&mut canvas, &text_font, label, PADDING, baseline, MUTED);
            draw_text(
                &mut canvas,
                &text_font,
                value,
                PADDING + label_width + LABEL_GAP,
                baseline,
                INK,
            );
            baseline += line_height;
        }

        let mut bytes = std::io::Cursor::new(Vec::new());
        image::DynamicImage::ImageRgba8(canvas)
            .write_to(&mut bytes, image::ImageFormat::Png)
            .map_err(|e| Error::malformed(format!("encoding the signature panel failed: {e}")))?;
        Ok(SignatureImage {
            bytes: bytes.into_inner(),
            // Drawn at `OVERSAMPLE` pixels per point, so this is the size the layout was designed
            // for. Placing it at anything else is scaling a picture of text.
            natural_size: Some((width as f32 / OVERSAMPLE, height as f32 / OVERSAMPLE)),
        })
    }
}

fn width_of<S, F>(font: &S, text: &str) -> f32
where
    S: ScaleFont<F>,
    F: ab_glyph::Font,
{
    text.chars().map(|c| font.h_advance(font.glyph_id(c))).sum()
}

fn draw_frame(canvas: &mut RgbaImage, colour: Rgba<u8>) {
    let (width, height) = canvas.dimensions();
    let thickness = BORDER.round().max(1.0) as u32;
    for y in 0..height {
        for x in 0..width {
            let edge =
                x < thickness || y < thickness || x + thickness >= width || y + thickness >= height;
            if edge {
                canvas.put_pixel(x, y, colour);
            }
        }
    }
}

fn draw_text<S, F>(
    canvas: &mut RgbaImage,
    font: &S,
    text: &str,
    x: f32,
    baseline: f32,
    colour: Rgba<u8>,
) where
    S: ScaleFont<F>,
    F: ab_glyph::Font,
{
    let mut caret = x;
    for character in text.chars() {
        let mut glyph = font.scaled_glyph(character);
        glyph.position = point(caret, baseline);
        caret += font.h_advance(glyph.id);

        let Some(outlined) = font.outline_glyph(glyph) else {
            continue; // whitespace, or a character the font has no outline for
        };
        let bounds = outlined.px_bounds();
        outlined.draw(|dx, dy, coverage| {
            let px = bounds.min.x as i32 + dx as i32;
            let py = bounds.min.y as i32 + dy as i32;
            if px < 0 || py < 0 {
                return;
            }
            let (px, py) = (px as u32, py as u32);
            if px >= canvas.width() || py >= canvas.height() {
                return;
            }
            blend(canvas.get_pixel_mut(px, py), colour, coverage);
        });
    }
}

/// Composite `colour` over what is already there, at `coverage`.
fn blend(pixel: &mut Rgba<u8>, colour: Rgba<u8>, coverage: f32) {
    let a = coverage.clamp(0.0, 1.0);
    for channel in 0..3 {
        let under = f32::from(pixel.0[channel]);
        let over = f32::from(colour.0[channel]);
        pixel.0[channel] = (under * (1.0 - a) + over * a).round() as u8;
    }
    pixel.0[3] = pixel.0[3].max((a * 255.0) as u8);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn block() -> SignatureBlock {
        SignatureBlock {
            title: "電子署名".into(),
            rows: vec![
                ("署名者".into(), "黒桐　幹也".into()),
                ("日時".into(), "2026-08-15 07:28:19 UTC".into()),
                ("理由".into(), "承認".into()),
            ],
        }
    }

    #[test]
    fn draws_a_panel_that_decodes_as_a_png() {
        let image = block().render().unwrap();
        let decoded = image::load_from_memory(&image.bytes).unwrap();
        assert!(
            decoded.width() > 100,
            "{}x{}",
            decoded.width(),
            decoded.height()
        );
        assert!(decoded.height() > 60);
        // Wider than tall: five short lines of text, not a square.
        assert!(decoded.width() > decoded.height());
    }

    #[test]
    fn the_same_block_renders_the_same_bytes() {
        // A signature's appearance should not depend on when it was drawn; a difference here
        // would mean the panel carries something the caller did not put in it.
        assert_eq!(
            block().render().unwrap().bytes,
            block().render().unwrap().bytes
        );
    }

    #[test]
    fn japanese_actually_appears() {
        // The bundled font is the whole reason this module exists. If a CJK glyph silently drew
        // nothing, the panel would still be a valid PNG — and blank where the name should be.
        let with_name = block().render().unwrap();
        let mut without = block();
        without.rows[0].1 = " ".into();
        let blank = without.render().unwrap();
        assert_ne!(
            with_name.bytes, blank.bytes,
            "the holder's name drew nothing: the font has no glyphs for it"
        );

        let drawn = image::load_from_memory(&with_name.bytes)
            .unwrap()
            .to_rgba8();
        let inked = drawn
            .pixels()
            .filter(|p| p.0[0] < 200 && p.0[2] < 200)
            .count();
        assert!(inked > 500, "almost nothing was drawn: {inked} dark pixels");
    }

    #[test]
    fn grows_to_fit_a_long_value() {
        let mut long = block();
        long.rows[0].1 = "非常に長い名前がここに入る場合でも枠に収まる".into();
        let wide = long.render().unwrap();
        let narrow = block().render().unwrap();
        let wide = image::load_from_memory(&wide.bytes).unwrap();
        let narrow = image::load_from_memory(&narrow.bytes).unwrap();
        assert!(
            wide.width() > narrow.width(),
            "the panel must widen rather than clip: {} vs {}",
            wide.width(),
            narrow.width()
        );
    }
}
