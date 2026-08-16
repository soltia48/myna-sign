//! Drawing the signature block that appears on the page.
//!
//! When the signer supplies no image of their own, the field would otherwise be invisible. This
//! draws a 署名欄 instead: 住所 above 氏名, which is the order a Japanese document is signed in and
//! read in, with the time underneath.
//!
//! # Why not the label-and-value panel other products draw
//!
//! Because of the shape it made. The old one grew a row at a time and a column as wide as its
//! longest value, so it arrived at roughly square for the common case and at 346pt — half the width
//! of the page — for one long 理由. A signature block is a shape people recognise, and that was not
//! it. `/Reason` and `/Location` are in the signature dictionary either way, and the interface
//! shows them when it verifies one.
//!
//! # These sizes are the sizes on paper
//!
//! [`super::default_placement`] takes the size out of [`SignatureImage::natural_size`], which this
//! sets from the layout below. Nothing scales it down on the way to the page, so a point here is a
//! point there, and choosing 9pt for the address means the address is 9pt on the paper.
//!
//! It also stops the drawing looking like a verdict. A bordered box of checked-looking fields is
//! what a viewer draws when it has *validated* a signature, and this program has not validated
//! anything at the moment it draws this.
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

/// Rendered at four times the size it is placed at, so the panel stays sharp when the page is
/// zoomed in a viewer or printed. Four rather than three because the type below is small in
/// points — 7pt at three times over is 21 pixels, which is where a CJK glyph starts to mush.
const OVERSAMPLE: f32 = 4.0;

/// The sizes are in points, and they are the sizes this is read at on the page.
///
/// The address is set near the body size of the documents this goes on — an invoice or a contract
/// runs at 10 or 10.5pt — because a signature block whose address is half the size of the address
/// it sits under reads as a footnote rather than as a signature. The name is set well above it:
/// it is the line the block exists for.
const TITLE_SIZE: f32 = 8.0 * OVERSAMPLE;
const LABEL_SIZE: f32 = 8.5 * OVERSAMPLE;
const ADDRESS_SIZE: f32 = 9.0 * OVERSAMPLE;
const NAME_SIZE: f32 = 17.0 * OVERSAMPLE;
const WHEN_SIZE: f32 = 8.0 * OVERSAMPLE;
const PADDING: f32 = 8.0 * OVERSAMPLE;
/// Between a label and what it labels.
const LABEL_GAP: f32 = 6.0 * OVERSAMPLE;
/// Baseline to baseline within the address, which is the only thing here that takes two lines.
const ADDRESS_LEADING: f32 = 1.25;
const RULE: f32 = 0.9 * OVERSAMPLE;

/// How wide the drawing is allowed to get.
///
/// Without a cap the width follows the longest string, and one long address turned the panel into
/// a 346pt banner across half the page. Past this the address wraps, and then elides. 280pt is
/// about 99mm: wide enough for a Tokyo address on one line, and still under a third of the usable
/// width of A4.
const MAX_WIDTH: f32 = 280.0 * OVERSAMPLE;
/// The address is allowed this many lines before what is left is cut.
const ADDRESS_LINES: usize = 2;

const INK: Rgba<u8> = Rgba([0x14, 0x18, 0x1D, 0xFF]);
/// The accent, darker than the interface's own. It carries the labels and the rule, never the
/// name — a document gets photocopied, and the name has to survive that. 11.0:1 on white, and
/// 12.1:1 once a copier has thrown the colour away.
const ACCENT: Rgba<u8> = Rgba([0x14, 0x3D, 0x6B, 0xFF]);
const PAPER: Rgba<u8> = Rgba([0xFF, 0xFF, 0xFF, 0xFF]);

/// What the 署名欄 says.
///
/// Four things, and no room for a fifth: see the note at the top of this module about what a row
/// costs. `/Reason` and `/Location` are deliberately not among them.
#[derive(Debug, Clone)]
pub struct SignatureBlock {
    /// The heading — what this drawing is.
    pub title: String,
    /// The signer's address as the 署名用証明書 records it, or `None` when it carries none.
    ///
    /// This is the address of a signature block, not `/Location`: that field is free text about
    /// where the signer happened to be, and is a different claim.
    pub address: Option<String>,
    /// The signer's name, or a stand-in while the certificate is still behind the password.
    pub name: String,
    /// When, written the way a person reads it.
    pub when: String,
}

impl Default for SignatureBlock {
    fn default() -> Self {
        SignatureBlock {
            title: "電子署名".into(),
            address: None,
            name: String::new(),
            when: String::new(),
        }
    }
}

impl SignatureBlock {
    /// The 署名欄 for a signature about to be made.
    ///
    /// The name and the address both come from the 署名用証明書, which is where a signature block's
    /// 氏名 and 住所 come from on paper too. The name falls back to the subject's `CN`; the address
    /// has no fallback, because inventing one would be putting a claim on the page that no
    /// certificate made.
    ///
    /// The time is the *claimed* signing time, which is the only one available while the signature
    /// is being made: a timestamp token does not exist until afterwards. It is labelled 日時 rather
    /// than anything that suggests it was attested.
    pub fn describe(certificate: &CertificateInfo, at: Timestamp) -> Self {
        let name = certificate
            .holder
            .name
            .clone()
            .or_else(|| certificate.common_name.clone())
            .unwrap_or_else(|| certificate.subject.clone());

        SignatureBlock {
            title: "電子署名".into(),
            address: certificate
                .holder
                .address
                .clone()
                .filter(|a| !a.trim().is_empty()),
            name,
            // Shown in Japan Standard Time: the panel is drawn for a Japanese document and read by
            // a person, not parsed. The instant that is machine-readable stays UTC — the PDF's
            // `/M`, the CMS `signingTime`, and any timestamp token.
            when: at.to_jst_minutes(),
        }
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
        let label_font = font.as_scaled(PxScale::from(LABEL_SIZE));
        let address_font = font.as_scaled(PxScale::from(ADDRESS_SIZE));
        let name_font = font.as_scaled(PxScale::from(NAME_SIZE));
        let when_font = font.as_scaled(PxScale::from(WHEN_SIZE));

        // Both labels sit in one column, so the values line up under each other the way they do on
        // a printed form.
        let label_width = width_of(&label_font, "住所").max(width_of(&label_font, "氏名"));
        let value_x = PADDING + label_width + LABEL_GAP;
        let budget = MAX_WIDTH - value_x - PADDING;

        let address = self
            .address
            .as_deref()
            .map(|a| wrap(&address_font, a, budget, ADDRESS_LINES))
            .unwrap_or_default();
        // A name is the one thing here worth widening the drawing for, but not without limit.
        let name = elide(&name_font, &self.name, budget);

        let value_width = address
            .iter()
            .map(|line| width_of(&address_font, line))
            .chain(std::iter::once(width_of(&name_font, &name)))
            .fold(0.0f32, f32::max);
        let width = (value_x + value_width + PADDING)
            .max(PADDING * 2.0 + width_of(&title_font, &self.title))
            .min(MAX_WIDTH);

        // Laid out top down, in the order it is read.
        let address_line = ADDRESS_SIZE * ADDRESS_LEADING;
        let mut y = PADDING + TITLE_SIZE;
        let title_baseline = y;
        y += TITLE_SIZE * 0.9;

        let address_top = y + ADDRESS_SIZE;
        y = address_top + address_line * address.len().saturating_sub(1) as f32;
        if !address.is_empty() {
            y += ADDRESS_SIZE * 0.5;
        }

        let name_baseline = y + NAME_SIZE;
        let rule_y = name_baseline + NAME_SIZE * 0.28;
        let when_baseline = rule_y + WHEN_SIZE * 1.6;
        let height = when_baseline + WHEN_SIZE * 0.35 + PADDING;

        let mut canvas = RgbaImage::from_pixel(
            width.ceil().max(1.0) as u32,
            height.ceil().max(1.0) as u32,
            PAPER,
        );

        draw_text(
            &mut canvas,
            &title_font,
            &self.title,
            PADDING,
            title_baseline,
            ACCENT,
        );

        for (index, line) in address.iter().enumerate() {
            let baseline = address_top + address_line * index as f32;
            if index == 0 {
                draw_text(&mut canvas, &label_font, "住所", PADDING, baseline, ACCENT);
            }
            draw_text(&mut canvas, &address_font, line, value_x, baseline, INK);
        }

        draw_text(
            &mut canvas,
            &label_font,
            "氏名",
            PADDING,
            name_baseline,
            ACCENT,
        );
        draw_text(&mut canvas, &name_font, &name, value_x, name_baseline, INK);

        // The rule is what makes this read as a signature block rather than as a caption. It runs
        // under the name only, which is the line a reader is being asked to take as the signature.
        draw_rule(&mut canvas, PADDING, width - PADDING, rule_y, ACCENT);

        draw_text(
            &mut canvas,
            &when_font,
            &self.when,
            PADDING,
            when_baseline,
            INK,
        );

        let mut bytes = std::io::Cursor::new(Vec::new());
        image::DynamicImage::ImageRgba8(canvas)
            .write_to(&mut bytes, image::ImageFormat::Png)
            .map_err(|e| Error::malformed(format!("encoding the signature panel failed: {e}")))?;
        Ok(SignatureImage {
            bytes: bytes.into_inner(),
            // Drawn at `OVERSAMPLE` pixels per point, so this is the size the layout was designed
            // for. Placing it at anything else is scaling a picture of text.
            natural_size: Some((width / OVERSAMPLE, height / OVERSAMPLE)),
        })
    }
}

/// Break `text` to `limit`, at most `lines` of it, marking the cut when there is more.
///
/// Japanese has no word boundaries to respect, so this breaks between characters — which is what
/// the script does. Digits are the exception and are kept whole: an address ends in a lot or a
/// room number, and `五〇八号室` broken after the `五` reads as a different number rather than as
/// the same one continued.
fn wrap<S, F>(font: &S, text: &str, limit: f32, lines: usize) -> Vec<String>
where
    S: ScaleFont<F>,
    F: ab_glyph::Font,
{
    let mut out: Vec<String> = Vec::new();
    let mut line = String::new();
    // Byte offset of the line being built, so the last one can take everything that is left.
    let mut consumed = 0usize;

    for unit in units(text) {
        let mut candidate = line.clone();
        candidate.push_str(unit);
        if !line.is_empty() && width_of(font, &candidate) > limit {
            if out.len() + 1 == lines {
                out.push(elide(font, &text[consumed..], limit));
                return out;
            }
            consumed += line.len();
            out.push(std::mem::take(&mut line));
        }
        line.push_str(unit);
    }
    if !line.is_empty() {
        out.push(line);
    }
    out
}

/// The pieces a line may be broken between: a run of digits, or a single character.
fn units(text: &str) -> Vec<&str> {
    fn digit(c: char) -> bool {
        c.is_ascii_digit() || ('０'..='９').contains(&c) || "〇一二三四五六七八九十".contains(c)
    }
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(first) = rest.chars().next() {
        let take = if digit(first) {
            rest.chars()
                .take_while(|c| digit(*c))
                .map(char::len_utf8)
                .sum()
        } else {
            first.len_utf8()
        };
        let (unit, remainder) = rest.split_at(take);
        out.push(unit);
        rest = remainder;
    }
    out
}

/// Cut `text` to `limit`, ending in an ellipsis when anything was removed.
fn elide<S, F>(font: &S, text: &str, limit: f32) -> String
where
    S: ScaleFont<F>,
    F: ab_glyph::Font,
{
    if width_of(font, text) <= limit {
        return text.to_owned();
    }
    let ellipsis = width_of(font, "…");
    let mut kept = String::new();
    for character in text.chars() {
        let mut candidate = kept.clone();
        candidate.push(character);
        if width_of(font, &candidate) + ellipsis > limit {
            break;
        }
        kept = candidate;
    }
    kept.push('…');
    kept
}

fn width_of<S, F>(font: &S, text: &str) -> f32
where
    S: ScaleFont<F>,
    F: ab_glyph::Font,
{
    text.chars().map(|c| font.h_advance(font.glyph_id(c))).sum()
}

/// The line under the name.
///
/// There is no border around any of this. A bordered box is how a viewer draws a signature it has
/// *checked*, and this is drawn before anything has been checked — see the top of the module.
fn draw_rule(canvas: &mut RgbaImage, from: f32, to: f32, y: f32, colour: Rgba<u8>) {
    let thickness = RULE.round().max(1.0) as u32;
    let (width, height) = canvas.dimensions();
    let top = y.round().max(0.0) as u32;
    for row in top..(top + thickness).min(height) {
        for column in (from.round().max(0.0) as u32)..(to.round().max(0.0) as u32).min(width) {
            canvas.put_pixel(column, row, colour);
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
            address: Some("東京都千代田区霞が関一丁目２番３号".into()),
            name: "黒桐　幹也".into(),
            when: "2026-08-15 16:28 JST".into(),
        }
    }

    fn decode(image: &SignatureImage) -> image::RgbaImage {
        image::load_from_memory(&image.bytes).unwrap().to_rgba8()
    }

    #[test]
    fn draws_a_panel_that_decodes_as_a_png() {
        let image = block().render().unwrap();
        let drawn = decode(&image);
        assert!(drawn.width() > 100, "{}x{}", drawn.width(), drawn.height());
        assert!(drawn.height() > 60);
    }

    /// The natural size is what `default_placement` puts on the page, so it is the size on paper.
    ///
    /// A signature block has to hold its own beside the sender's address on an invoice, which runs
    /// at about 10.5pt over roughly 190pt — and it has to stay small enough to be a signature
    /// rather than a second letterhead.
    #[test]
    fn is_placed_at_a_size_a_signature_block_is_read_at() {
        for panel in [
            block(),
            SignatureBlock {
                address: None,
                ..block()
            },
        ] {
            let (width, height) = panel.render().unwrap().natural_size.unwrap();
            assert!(
                (70.0..=110.0).contains(&height),
                "{width:.0}x{height:.0}pt is not the height of a signature block"
            );
            assert!(width >= 80.0, "{width:.0}pt wide");
            // A4 leaves 523pt between the margins `default_placement` uses.
            assert!(width <= 300.0, "{width:.0}pt wide");
        }
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
        let blank = SignatureBlock {
            name: " ".into(),
            ..block()
        }
        .render()
        .unwrap();
        assert_ne!(
            with_name.bytes, blank.bytes,
            "the holder's name drew nothing: the font has no glyphs for it"
        );

        let inked = decode(&with_name)
            .pixels()
            .filter(|p| p.0[0] < 200 && p.0[2] < 200)
            .count();
        assert!(inked > 500, "almost nothing was drawn: {inked} dark pixels");
    }

    /// One long address used to make the drawing a 346pt banner across half the page.
    #[test]
    fn a_long_address_wraps_instead_of_widening_without_limit() {
        let long = SignatureBlock {
            address: Some(
                "北海道川上郡弟子屈町字屈斜路原野九十九番地の三　サンシャインコーポラス第二別館五〇八号室"
                    .into(),
            ),
            ..block()
        };
        let (width, _) = long.render().unwrap().natural_size.unwrap();
        assert!(
            width <= MAX_WIDTH / OVERSAMPLE + 1.0,
            "the panel grew to {width:.0}pt"
        );
    }

    #[test]
    fn a_name_too_long_for_the_panel_is_elided_rather_than_widening_it() {
        let long = SignatureBlock {
            name: "特定非営利活動法人日本電子署名普及協会代表理事山田太郎".into(),
            ..block()
        };
        let (width, _) = long.render().unwrap().natural_size.unwrap();
        assert!(width <= MAX_WIDTH / OVERSAMPLE + 1.0, "{width:.0}pt");
    }

    #[test]
    fn a_block_without_an_address_still_draws() {
        // Not every 署名用証明書 carries one, and inventing an address would be putting a claim on
        // the page that no certificate made.
        let image = SignatureBlock {
            address: None,
            ..block()
        }
        .render()
        .unwrap();
        assert!(decode(&image).width() > 50);
    }

    /// A room number split across lines reads as a different number.
    #[test]
    fn digits_are_not_broken_across_lines() {
        let font = FontRef::try_from_slice(FONT).unwrap();
        let scaled = font.as_scaled(PxScale::from(ADDRESS_SIZE));
        let text = "千代田区一丁目２番３号　第二別館五〇八号室";
        for limit in [40.0, 60.0, 80.0, 100.0, 140.0] {
            let lines = wrap(&scaled, text, limit * OVERSAMPLE, 2);
            for pair in lines.windows(2) {
                let ends = pair[0].chars().next_back().unwrap();
                let starts = pair[1].chars().next().unwrap();
                assert!(
                    !(digit(ends) && digit(starts)),
                    "broke {text:?} between {ends} and {starts} at limit {limit}"
                );
            }
        }
    }

    fn digit(c: char) -> bool {
        c.is_ascii_digit() || ('０'..='９').contains(&c) || "〇一二三四五六七八九十".contains(c)
    }

    #[test]
    fn what_will_not_fit_is_marked_rather_than_dropped() {
        let font = FontRef::try_from_slice(FONT).unwrap();
        let scaled = font.as_scaled(PxScale::from(ADDRESS_SIZE));
        let lines = wrap(&scaled, "あ".repeat(200).as_str(), 40.0 * OVERSAMPLE, 2);
        assert_eq!(lines.len(), 2);
        assert!(
            lines.last().unwrap().ends_with('…'),
            "silently dropped the rest: {lines:?}"
        );
    }
}
