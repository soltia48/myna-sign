//! Cross-checks against implementations that are not this one.
//!
//! Verifying our own signatures with our own verifier proves that the two agree, which is not the
//! same as either being right. These tests hand the output to `gpg` and `openssl ts` and let those
//! pass judgement. When they pass, the format is right; when they fail, ours is wrong, whatever
//! the unit tests say.
//!
//! Each test skips if the tool it needs is missing, and the ones that reach the network are
//! `#[ignore]` so that an outage cannot turn CI red. Run them with
//! `cargo test --features soft-signer -- --ignored`.

#![cfg(feature = "soft-signer")]

use std::path::{Path, PathBuf};
use std::process::Command;

use myna_sign_core::openpgp::{self, SignOptions};
use myna_sign_core::signer::SoftSigner;
use myna_sign_core::time::Timestamp;

/// Whether a program is on the PATH.
fn have(program: &str) -> bool {
    Command::new(program)
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Run `gpg` against a throwaway home directory, so this never touches the user's keyring.
///
/// Everything is named relative to `dir`, and `dir` is where the process runs. That is not tidiness:
/// the `gpg` on a Windows runner is the MSYS build that Git for Windows carries, and it decides
/// whether a path is absolute by POSIX rules. Handed `C:\Users\...` for `--homedir` it sees no
/// leading `/`, calls it relative, and joins it onto its own working directory — which is how the
/// keyring ends up at `/d/a/myna-sign/myna-sign/crates/myna-sign-core/C:\Users\...`, no key can be
/// imported, and every verification fails for a reason that has nothing to do with the signature.
/// A `.` means the same thing to both builds.
fn gpg_in(dir: &TempDir, args: &[&str]) -> std::process::Output {
    Command::new("gpg")
        .current_dir(dir.path())
        .arg("--homedir")
        .arg(".")
        .arg("--batch")
        .args(args)
        .output()
        .expect("gpg failed to start")
}

/// Where a throwaway directory goes.
///
/// Not `std::env::temp_dir()` on Unix. On macOS that is `$TMPDIR`, a per-user directory under
/// `/var/folders` that canonicalises to about ninety characters — and `gpg` puts the agent's Unix
/// socket inside whatever home directory it is given. `sun_path` holds 104 bytes there, so
/// `<homedir>/S.gpg-agent` does not fit, and every invocation ends with "can't connect to the
/// gpg-agent: File name too long" *after* doing its work correctly. A short base keeps the socket
/// nameable. Windows has no such limit and no such socket.
fn temp_base() -> PathBuf {
    #[cfg(unix)]
    {
        PathBuf::from("/tmp")
    }
    #[cfg(not(unix))]
    {
        std::env::temp_dir()
    }
}

/// A directory that goes away when the test does.
struct TempDir(PathBuf);

impl TempDir {
    fn new(name: &str) -> Self {
        let mut path = temp_base();
        path.push(format!(
            "myna-sign-{name}-{}-{}",
            std::process::id(),
            // Distinguish concurrent tests without pulling in a clock or a random number
            // generator: the address of a stack local is unique among live frames.
            &format!("{:p}", &name)[2..]
        ));
        std::fs::create_dir_all(&path).unwrap();
        // `gpg` warns about a home directory other people can read, which is fair of it. The
        // warning is noise in a log somebody only opens when something else has gone wrong.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        TempDir(path)
    }

    fn join(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn soft_signer() -> SoftSigner {
    SoftSigner::generate(
        "CN=Interop Test,C=JP",
        Timestamp::from_unix_seconds(1_700_000_000),
        3650,
    )
    .unwrap()
}

#[test]
fn gpg_verifies_a_detached_signature_we_made() {
    if !have("gpg") {
        eprintln!("skipping: gpg is not installed");
        return;
    }

    let dir = TempDir::new("gpg");
    let document = dir.join("document.txt");
    std::fs::write(&document, b"The bytes that were signed.\n").unwrap();

    let mut signer = soft_signer();
    let public_key =
        openpgp::export_certificate(&mut signer, "Interop Test <t@example.invalid>").unwrap();
    std::fs::write(dir.join("public.asc"), &public_key).unwrap();

    let signature = openpgp::sign_detached(
        &mut signer,
        std::fs::File::open(&document).unwrap(),
        &SignOptions::default(),
    )
    .unwrap();
    std::fs::write(dir.join("document.txt.asc"), &signature.armored).unwrap();

    let imported = gpg_in(&dir, &["--import", "public.asc"]);
    // What gpg says it did, not what it exits with. Its exit status also carries things that have
    // nothing to do with the key — an unreachable gpg-agent is the one that bites here, and it
    // reports the import as done and then exits non-zero anyway.
    let stderr = String::from_utf8_lossy(&imported.stderr);
    assert!(
        stderr.contains("imported: 1"),
        "gpg would not import the key we exported:\n{stderr}"
    );

    let verified = gpg_in(&dir, &["--verify", "document.txt.asc", "document.txt"]);
    let stderr = String::from_utf8_lossy(&verified.stderr);
    // The verdict is the sentence, not the exit status: gpg exits non-zero for an unreachable
    // agent as readily as for a signature that does not check out, and only one of those is what
    // this test is asking about. The status goes in the message so a failure is still diagnosable.
    assert!(
        stderr.contains("Good signature"),
        "gpg did not call it a good signature (exit {}):\n{stderr}",
        verified.status
    );
}

#[test]
fn gpg_rejects_a_signature_over_a_document_that_changed() {
    if !have("gpg") {
        eprintln!("skipping: gpg is not installed");
        return;
    }

    let dir = TempDir::new("gpg-tamper");
    let document = dir.join("document.txt");
    std::fs::write(&document, b"original\n").unwrap();

    let mut signer = soft_signer();
    std::fs::write(
        dir.join("public.asc"),
        openpgp::export_certificate(&mut signer, "Interop Test <t@example.invalid>").unwrap(),
    )
    .unwrap();
    let signature = openpgp::sign_detached(
        &mut signer,
        std::fs::File::open(&document).unwrap(),
        &SignOptions::default(),
    )
    .unwrap();
    std::fs::write(dir.join("document.txt.asc"), &signature.armored).unwrap();

    // Change the document after signing.
    std::fs::write(&document, b"tampered\n").unwrap();

    // Checked rather than discarded: an import that failed leaves gpg with no key, and then the
    // verification below fails for that reason instead of the one under test.
    let imported = gpg_in(&dir, &["--import", "public.asc"]);
    // What gpg says it did, not what it exits with. Its exit status also carries things that have
    // nothing to do with the key — an unreachable gpg-agent is the one that bites here, and it
    // reports the import as done and then exits non-zero anyway.
    let stderr = String::from_utf8_lossy(&imported.stderr);
    assert!(
        stderr.contains("imported: 1"),
        "gpg would not import the key we exported:\n{stderr}"
    );

    let verified = gpg_in(&dir, &["--verify", "document.txt.asc", "document.txt"]);
    // Not just a non-zero exit: gpg exits non-zero for a missing key, an unreadable file and a
    // dozen other things that are not "this signature does not match". On the Windows runner it
    // was doing exactly that, and this test passed for months without checking a signature.
    let stderr = String::from_utf8_lossy(&verified.stderr);
    assert!(
        !verified.status.success(),
        "gpg accepted a signature over a document that changed:\n{stderr}"
    );
    assert!(
        stderr.contains("BAD signature"),
        "gpg rejected the signature, but not for the reason under test:\n{stderr}"
    );
}

/// The certificate notation must not stop other OpenPGP implementations from reading the
/// signature. It is not critical, so `gpg` should ignore it — and the test above already proves
/// that, since every signature it verifies carries one. This checks the notation is actually
/// there, so that test is not passing vacuously.
#[test]
fn the_signature_carries_the_certificate_and_gpg_still_reads_it() {
    let mut signer = soft_signer();
    let signature =
        openpgp::sign_detached(&mut signer, &b"doc"[..], &SignOptions::default()).unwrap();
    let parsed = openpgp::embedded_certificate(&signature.signature)
        .unwrap()
        .expect("the certificate should be embedded by default");
    assert_eq!(parsed.der(), signer_certificate_der(&signer));
}

fn signer_certificate_der(signer: &SoftSigner) -> &[u8] {
    use myna_sign_core::DigestSigner as _;
    signer.certificate().der()
}

// --- RFC 3161 ---------------------------------------------------------------------------------

/// The two authorities the interface offers, exercised for real.
///
/// Ignored by default: an authority being down is not a bug in this program.
#[test]
#[ignore = "reaches the network"]
#[cfg(feature = "tsa-http")]
fn both_timestamp_authorities_answer_and_their_tokens_verify() {
    use myna_sign_core::tsa::{self, BlockingHttp, TsaPreset};

    let http = BlockingHttp::default();
    let signature_value = b"a signature value to be timestamped";

    for preset in [TsaPreset::FreeTsa, TsaPreset::DigiCert] {
        let token = tsa::fetch(&http, preset.url(), signature_value)
            .unwrap_or_else(|e| panic!("{}: {e}", preset.label()));

        let verification =
            tsa::verify_token_with(&token, signature_value, &preset.anchors()).unwrap();
        assert!(
            verification.imprint_matches,
            "{}: the token is over a different imprint",
            preset.label()
        );
        assert!(
            verification.signature_verified,
            "{}: the token's own signature does not verify",
            preset.label()
        );
        assert!(
            verification.timestamping_eku,
            "{}: the responder certificate has no critical timeStamping EKU",
            preset.label()
        );
        assert!(
            verification.chain.verified,
            "{}: {:?}",
            preset.label(),
            verification.chain
        );
        assert!(
            verification.verified,
            "{}: {verification:?}",
            preset.label()
        );

        // And the token must be over *that* signature and no other.
        let other =
            tsa::verify_token_with(&token, b"a different value", &preset.anchors()).unwrap();
        assert!(!other.imprint_matches);
        assert!(!other.verified);

        eprintln!(
            "{}: {} — policy {}, chain {:?}",
            preset.label(),
            verification.gen_time,
            verification.policy,
            verification.chain.anchor
        );
    }
}

/// `openssl ts -verify` is the second opinion on our token handling.
#[test]
#[ignore = "reaches the network"]
#[cfg(feature = "tsa-http")]
fn openssl_verifies_a_token_we_fetched() {
    use myna_sign_core::tsa::{self, BlockingHttp, HttpPost as _, TsaPreset};

    if !have("openssl") {
        eprintln!("skipping: openssl is not installed");
        return;
    }

    let dir = TempDir::new("tsa");
    let signature_value = b"a signature value to be timestamped";

    let http = BlockingHttp::default();
    let request = tsa::build_request(signature_value).unwrap();
    let response = http
        .post(
            tsa::TsaPreset::FreeTsa.url(),
            tsa::REQUEST_CONTENT_TYPE,
            &request.der,
        )
        .unwrap();
    let token = request.parse_response(&response).unwrap();

    // openssl wants the query and the reply, plus the root to anchor at.
    std::fs::write(dir.join("query.tsq"), &request.der).unwrap();
    std::fs::write(dir.join("reply.tsr"), &response).unwrap();
    std::fs::write(
        dir.join("root.pem"),
        pem(myna_sign_core::tsa::roots::FREETSA_ROOT),
    )
    .unwrap();

    let output = Command::new("openssl")
        .args(["ts", "-verify", "-in"])
        .arg(dir.join("reply.tsr"))
        .arg("-queryfile")
        .arg(dir.join("query.tsq"))
        .arg("-CAfile")
        .arg(dir.join("root.pem"))
        .output()
        .expect("openssl failed to start");
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("Verification: OK"),
        "openssl would not verify the exchange we built:\n{combined}"
    );

    // And our own verifier agrees with it.
    let ours =
        tsa::verify_token_with(&token, signature_value, &TsaPreset::FreeTsa.anchors()).unwrap();
    assert!(ours.verified, "{ours:?}");
}

fn pem(der: &[u8]) -> String {
    use base64::Engine as _;
    let body = base64::engine::general_purpose::STANDARD.encode(der);
    let mut out = String::from("-----BEGIN CERTIFICATE-----\n");
    for chunk in body.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).unwrap());
        out.push('\n');
    }
    out.push_str("-----END CERTIFICATE-----\n");
    out
}

// --- PDF --------------------------------------------------------------------------------------

/// A one page PDF with nothing on it.
fn blank_pdf() -> Vec<u8> {
    use lopdf::{Document, Object, dictionary};
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
            "Type" => "Pages", "Kids" => vec![page_id.into()], "Count" => 1,
        }),
    );
    let catalog_id = doc.add_object(dictionary! { "Type" => "Catalog", "Pages" => pages_id });
    doc.trailer.set("Root", catalog_id);
    let mut bytes = Vec::new();
    doc.save_to(&mut bytes).unwrap();
    bytes
}

fn pdfsig(path: &Path) -> String {
    let output = Command::new("pdfsig")
        .arg(path)
        .output()
        .expect("pdfsig failed to start");
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

#[test]
fn pdfsig_accepts_a_signature_we_made() {
    if !have("pdfsig") {
        eprintln!("skipping: pdfsig (poppler-utils) is not installed");
        return;
    }

    let dir = TempDir::new("pdfsig");
    let path = dir.join("signed.pdf");

    let mut signer = soft_signer();
    let options = myna_sign_core::pdf::PdfSignOptions {
        reason: Some("Interop".into()),
        ..Default::default()
    };
    let signed = myna_sign_core::pdf::sign(&mut signer, &blank_pdf(), &options).unwrap();
    std::fs::write(&path, &signed.bytes).unwrap();

    let report = pdfsig(&path);
    assert!(
        report.contains("Signature is Valid"),
        "pdfsig would not accept our signature:\n{report}"
    );
    // The certificate is self-signed here, so pdfsig will not trust the issuer — that is expected
    // and is a different statement from the signature being bad.
    assert!(
        report.contains("Interop Test"),
        "pdfsig did not read the signer's name:\n{report}"
    );
}

#[test]
fn pdfsig_rejects_a_document_changed_after_signing() {
    if !have("pdfsig") {
        eprintln!("skipping: pdfsig (poppler-utils) is not installed");
        return;
    }

    let dir = TempDir::new("pdfsig-tamper");
    let path = dir.join("tampered.pdf");

    let mut signer = soft_signer();
    let mut bytes = myna_sign_core::pdf::sign(
        &mut signer,
        &blank_pdf(),
        &myna_sign_core::pdf::PdfSignOptions::default(),
    )
    .unwrap()
    .bytes;

    // Flip a byte inside the signed range.
    let range = myna_sign_core::pdf::verify::byte_range_of(&bytes).unwrap();
    bytes[range[1] / 2] ^= 0x01;
    std::fs::write(&path, &bytes).unwrap();

    let report = pdfsig(&path);
    assert!(
        !report.contains("Signature is Valid"),
        "pdfsig accepted a document that changed after signing:\n{report}"
    );
}

#[test]
fn pdfsig_accepts_a_visible_signature_with_an_image() {
    if !have("pdfsig") {
        eprintln!("skipping: pdfsig (poppler-utils) is not installed");
        return;
    }

    let mut buffer = image::RgbaImage::new(64, 32);
    for (x, y, pixel) in buffer.enumerate_pixels_mut() {
        let ink = (x / 8 + y / 8) % 2 == 0;
        *pixel = image::Rgba([180, 20, 20, if ink { 255 } else { 0 }]);
    }
    let mut png = std::io::Cursor::new(Vec::new());
    image::DynamicImage::ImageRgba8(buffer)
        .write_to(&mut png, image::ImageFormat::Png)
        .unwrap();

    let dir = TempDir::new("pdfsig-image");
    let path = dir.join("stamped.pdf");

    let mut signer = soft_signer();
    let options = myna_sign_core::pdf::PdfSignOptions {
        appearance: Some(myna_sign_core::pdf::Appearance {
            page: 1,
            rect: [400.0, 60.0, 545.0, 130.0],
            image: Some(myna_sign_core::pdf::SignatureImage::from_bytes(
                png.into_inner(),
            )),
        }),
        ..Default::default()
    };
    let signed = myna_sign_core::pdf::sign(&mut signer, &blank_pdf(), &options).unwrap();
    std::fs::write(&path, &signed.bytes).unwrap();

    let report = pdfsig(&path);
    assert!(
        report.contains("Signature is Valid"),
        "an appearance stream must not disturb the signature:\n{report}"
    );
}

/// Sign, timestamp, and have `pdfsig` read both.
#[test]
#[ignore = "reaches the network"]
#[cfg(feature = "tsa-http")]
fn pdfsig_reads_a_timestamp_we_attached() {
    use myna_sign_core::tsa::{self, BlockingHttp, TsaPreset};

    let dir = TempDir::new("pdfsig-tsa");
    let path = dir.join("timestamped.pdf");

    let mut signer = soft_signer();
    let mut signed = myna_sign_core::pdf::sign(
        &mut signer,
        &blank_pdf(),
        &myna_sign_core::pdf::PdfSignOptions::default(),
    )
    .unwrap();

    let http = BlockingHttp::default();
    let token = tsa::fetch(&http, TsaPreset::DigiCert.url(), &signed.signature_value).unwrap();
    signed.attach_timestamp(&token).unwrap();
    std::fs::write(&path, &signed.bytes).unwrap();

    // Our own verifier: the signature still holds and the timestamp checks out.
    let results = myna_sign_core::pdf::verify(&signed.bytes, &Default::default()).unwrap();
    assert!(results[0].signature_verified, "{:#?}", results[0]);
    assert!(results[0].document_digest_matches);
    let stamp = results[0]
        .timestamp
        .as_ref()
        .expect("the timestamp is there");
    assert!(stamp.verified, "{stamp:#?}");
    eprintln!("timestamp: {} via {:?}", stamp.gen_time, stamp.chain.anchor);

    if have("pdfsig") {
        let report = pdfsig(&path);
        assert!(
            report.contains("Signature is Valid"),
            "attaching a timestamp must not disturb the signature:\n{report}"
        );
    }
}

// --- Cleartext signatures -----------------------------------------------------------------------

/// The canonicalisation rules for a cleartext signature are easy to get subtly wrong, and a
/// signature that verifies only against our own verifier would look fine until someone else tried
/// it. `gpg` is the judge.
#[test]
fn gpg_verifies_a_cleartext_signature() {
    if !have("gpg") {
        eprintln!("skipping: gpg is not installed");
        return;
    }

    let dir = TempDir::new("gpg-cleartext");
    // Trailing whitespace, a dash-led line, and a non-ASCII line: the three things the format has
    // rules about.
    let text = "契約書\nline with trailing spaces   \n-----not armor-----\nlast line";

    let mut signer = soft_signer();
    std::fs::write(
        dir.join("public.asc"),
        openpgp::export_certificate(&mut signer, "Interop Test <t@example.invalid>").unwrap(),
    )
    .unwrap();

    let signed = openpgp::sign_cleartext(&mut signer, text, &SignOptions::default()).unwrap();
    let path = dir.join("message.asc");
    std::fs::write(&path, &signed.armored).unwrap();

    // Checked rather than discarded: an import that failed leaves gpg with no key, and then the
    // verification below fails for that reason instead of the one under test.
    let imported = gpg_in(&dir, &["--import", "public.asc"]);
    // What gpg says it did, not what it exits with. Its exit status also carries things that have
    // nothing to do with the key — an unreachable gpg-agent is the one that bites here, and it
    // reports the import as done and then exits non-zero anyway.
    let stderr = String::from_utf8_lossy(&imported.stderr);
    assert!(
        stderr.contains("imported: 1"),
        "gpg would not import the key we exported:\n{stderr}"
    );

    let verified = gpg_in(&dir, &["--verify", "message.asc"]);
    let stderr = String::from_utf8_lossy(&verified.stderr);
    assert!(
        stderr.contains("Good signature"),
        "gpg rejected our cleartext signature (exit {}):\n{stderr}",
        verified.status
    );

    // And our own verifier agrees.
    let ours = openpgp::verify_cleartext(&signed.armored, &Default::default()).unwrap();
    assert!(ours.signature_verified, "{ours:#?}");
}

#[test]
fn a_cleartext_message_edited_after_signing_is_caught() {
    let mut signer = soft_signer();
    let signed =
        openpgp::sign_cleartext(&mut signer, "the agreed text", &SignOptions::default()).unwrap();

    let tampered = String::from_utf8(signed.armored.clone())
        .unwrap()
        .replace("the agreed text", "some other text");
    let result = openpgp::verify_cleartext(tampered.as_bytes(), &Default::default()).unwrap();
    assert!(
        !result.signature_verified,
        "an edited cleartext message must not verify"
    );
}

/// Round-tripping must recover exactly the bytes that were hashed, dash-escaping undone.
#[test]
fn splitting_a_cleartext_message_recovers_what_was_signed() {
    let mut signer = soft_signer();
    let text = "-dash led\nplain\n";
    let signed = openpgp::sign_cleartext(&mut signer, text, &SignOptions::default()).unwrap();

    let rendered = String::from_utf8(signed.armored.clone()).unwrap();
    assert!(
        rendered.contains("\n- -dash led\n"),
        "a line starting with a dash must be escaped:\n{rendered}"
    );

    let (recovered, _) = openpgp::split_cleartext(&signed.armored).unwrap();
    assert_eq!(recovered, "-dash led\r\nplain\r\n");
}

/// The OpenPGP timestamp path, end to end.
///
/// This is the test that was missing. The timestamp lives in the signature's *unhashed* area,
/// which `Signature::notation_data` deliberately does not return — so for a while every timestamp
/// attached to a `.asc` was written correctly and then invisible to this program's own verifier.
/// Only the PDF path had been exercised, and it does not go through the same code.
#[test]
#[ignore = "reaches the network"]
#[cfg(feature = "tsa-http")]
fn an_openpgp_timestamp_survives_a_round_trip() {
    use myna_sign_core::tsa::{self, BlockingHttp, TsaPreset};

    let http = BlockingHttp::default();
    let document = b"the document that was signed";

    for cleartext in [false, true] {
        let mut signer = soft_signer();
        let mut signature = if cleartext {
            openpgp::sign_cleartext(
                &mut signer,
                "the document that was signed",
                &SignOptions::default(),
            )
            .unwrap()
        } else {
            openpgp::sign_detached(&mut signer, &document[..], &SignOptions::default()).unwrap()
        };

        let token = tsa::fetch(
            &http,
            TsaPreset::DigiCert.url(),
            &signature.signature_value().unwrap(),
        )
        .unwrap();
        signature.attach_timestamp(&token).unwrap();

        // The framing must survive: a cleartext message that came back as a bare signature would
        // have lost the text it signs.
        if cleartext {
            assert!(
                signature
                    .armored
                    .starts_with(b"-----BEGIN PGP SIGNED MESSAGE-----"),
                "attaching a timestamp destroyed the cleartext framing"
            );
        }

        let result = if cleartext {
            openpgp::verify_cleartext(&signature.armored, &Default::default()).unwrap()
        } else {
            openpgp::verify_detached(&signature.armored, &document[..], &Default::default())
                .unwrap()
        };

        assert!(result.signature_verified, "{result:#?}");
        let stamp = result.timestamp.as_ref().unwrap_or_else(|| {
            panic!("the timestamp is not readable back (cleartext: {cleartext})")
        });
        assert!(stamp.verified, "{stamp:#?}");
        eprintln!(
            "cleartext={cleartext}: {} via {:?}",
            stamp.gen_time, stamp.chain.anchor
        );
    }
}

/// The generated panel goes into a real PDF and `pdfsig` still accepts the signature.
///
/// Drawing on the page is the one part of signing that touches the document's *content*, so it is
/// also the one most able to break the file. This checks the whole path: draw, place, sign, and
/// hand the result to something that is not this program.
#[test]
fn pdfsig_accepts_a_signature_with_a_generated_panel() {
    use myna_sign_core::DigestSigner as _;
    use myna_sign_core::pdf;
    use myna_sign_core::x509::CertificateInfo;

    if !have("pdfsig") {
        eprintln!("skipping: pdfsig (poppler-utils) is not installed");
        return;
    }

    let dir = TempDir::new("panel");
    let path = dir.join("panelled.pdf");
    let original = blank_pdf();

    let mut signer = soft_signer();
    let certificate = CertificateInfo::read(signer.certificate()).unwrap();
    let panel = pdf::SignatureBlock::describe(
        &certificate,
        Timestamp::from_unix_seconds(1_786_775_188),
        Some("承認"),
        Some("東京"),
    )
    .render()
    .unwrap();

    // Placed by its own proportions, in the corner, because nobody dragged a rectangle.
    let appearance = pdf::default_placement(&original, 1, &panel).unwrap();
    let (width, height) = appearance.size();
    assert!(
        width > 80.0 && height > 80.0,
        "the panel would be illegible at {width}x{height}pt"
    );
    assert!(
        appearance.rect[2] <= 595.0 && appearance.rect[1] >= 0.0,
        "the panel is off the page: {:?}",
        appearance.rect
    );

    let options = pdf::PdfSignOptions {
        reason: Some("承認".into()),
        location: Some("東京".into()),
        appearance: Some(appearance),
        ..Default::default()
    };
    let signed = pdf::sign(&mut signer, &original, &options).unwrap();
    std::fs::write(&path, &signed.bytes).unwrap();

    let report = pdfsig(&path);
    assert!(
        report.contains("Signature is Valid"),
        "a generated panel must not disturb the signature:\n{report}"
    );

    let ours = pdf::verify(&signed.bytes, &Default::default()).unwrap();
    assert!(
        ours[0].byte_range_sound && ours[0].document_digest_matches,
        "{ours:#?}"
    );
}

/// An image is fitted into the field, not stretched to it.
#[test]
fn a_stamp_keeps_its_proportions_in_a_field_of_a_different_shape() {
    use myna_sign_core::pdf;

    // A wide panel dropped into a tall, narrow rectangle.
    let panel = pdf::SignatureBlock {
        title: "電子署名".into(),
        rows: vec![("署名者".into(), "黒桐　幹也".into())],
    }
    .render()
    .unwrap();
    let (natural_width, natural_height) = panel.natural_size.unwrap();

    let mut signer = soft_signer();
    let options = pdf::PdfSignOptions {
        appearance: Some(pdf::Appearance {
            page: 1,
            rect: [100.0, 100.0, 160.0, 400.0], // 60 wide, 300 tall
            image: Some(panel),
        }),
        ..Default::default()
    };
    let signed = pdf::sign(&mut signer, &blank_pdf(), &options).unwrap();

    // The content stream scales the image by the same factor in both directions.
    let text = String::from_utf8_lossy(&signed.bytes);
    let matrix = text
        .split("cm /Im0 Do Q")
        .next()
        .and_then(|s| s.rsplit('q').next())
        .expect("an appearance stream");
    let numbers: Vec<f32> = matrix
        .split_whitespace()
        .filter_map(|n| n.parse().ok())
        .collect();
    assert_eq!(numbers.len(), 6, "unexpected matrix: {matrix:?}");
    let (drawn_width, drawn_height) = (numbers[0], numbers[3]);

    let wanted = natural_width / natural_height;
    let got = drawn_width / drawn_height;
    assert!(
        (wanted - got).abs() < 0.01,
        "the panel was distorted: {wanted:.3} became {got:.3}"
    );
    assert!(
        drawn_width <= 60.01 && drawn_height <= 300.01,
        "it overflows the field"
    );
}

/// Signing a document that already has annotations and a form, which is what a real one looks
/// like. `pdfsig` reads it; the structural checks are unit tests in `pdf::sign`.
#[test]
fn pdfsig_accepts_a_signature_added_to_an_existing_form() {
    if !have("pdfsig") {
        eprintln!("skipping: pdfsig (poppler-utils) is not installed");
        return;
    }

    let dir = TempDir::new("pdfsig-form");
    let path = dir.join("form.pdf");

    let mut signer = soft_signer();
    let signed = myna_sign_core::pdf::sign(
        &mut signer,
        &form_pdf(),
        &myna_sign_core::pdf::PdfSignOptions::default(),
    )
    .unwrap();
    std::fs::write(&path, &signed.bytes).unwrap();

    let report = pdfsig(&path);
    assert!(
        report.contains("Signature is Valid"),
        "adding a signature to an existing form broke it:\n{report}"
    );
}

/// A PDF with a separate `/Annots` object and an `/AcroForm` carrying `/DR`.
fn form_pdf() -> Vec<u8> {
    let objects: [(u32, &[u8]); 8] = [
        (1, b"<</Type/Catalog/Pages 2 0 R/AcroForm 8 0 R>>"),
        (
            2,
            b"<</Type/Pages/Kids[3 0 R]/Count 1/MediaBox[0 0 595 842]>>",
        ),
        (3, b"<</Type/Page/Parent 2 0 R/Annots 6 0 R>>"),
        (
            4,
            b"<</Type/Annot/Subtype/Widget/FT/Tx/T(name)/Rect[50 700 300 730]>>",
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
