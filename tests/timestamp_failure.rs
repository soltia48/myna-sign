//! What happens when the timestamp authority is unreachable.
//!
//! By the time a timestamp is requested the card has already signed. An authority that is down has
//! nothing to do with whether the signature is good, so losing the signature over it would throw
//! away a password entry and a card operation for an unrelated reason. These tests pin that.
//!
//! They use `--soft-key`, so no card and no reader are needed.

use std::path::{Path, PathBuf};
use std::process::Command;

/// A port nothing listens on. Discard is reserved and refused immediately, so these tests do not
/// wait for a timeout.
const DEAD_TSA: &str = "http://127.0.0.1:9/tsr";

struct TempDir(PathBuf);

impl TempDir {
    fn new(name: &str) -> Self {
        let mut path = std::env::temp_dir();
        path.push(format!("myna-sign-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();
        TempDir(path)
    }
    fn join(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn cli() -> Command {
    Command::new(env!("CARGO_BIN_EXE_myna-sign"))
}

fn document(dir: &TempDir) -> PathBuf {
    let path = dir.join("document.txt");
    std::fs::write(&path, b"the bytes that were signed\n").unwrap();
    path
}

fn assert_verifies(signature: &Path, document: &Path) {
    let output = cli()
        .arg("verify")
        .arg(signature)
        .arg(document)
        .output()
        .expect("the CLI failed to start");
    let json = String::from_utf8_lossy(&output.stdout);
    assert!(
        json.contains("\"signatureVerified\": true"),
        "the signature that was kept does not verify:\n{json}"
    );
}

#[test]
fn an_unreachable_authority_does_not_cost_the_signature() {
    let dir = TempDir::new("keep");
    let document_path = document(&dir);

    let output = cli()
        .args([
            "--soft-key",
            "--tsa",
            "custom",
            "--tsa-url",
            DEAD_TSA,
            "sign",
        ])
        .arg(&document_path)
        .output()
        .expect("the CLI failed to start");

    assert!(
        output.status.success(),
        "signing should succeed without a timestamp:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let signature = dir.join("document.txt.asc");
    assert!(
        signature.exists(),
        "the signature was thrown away because a timestamp authority was down"
    );
    assert_verifies(&signature, &document_path);

    // And the user is told, rather than left to discover the missing timestamp later.
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("could not get a timestamp"),
        "a missing timestamp must be said out loud:\n{stderr}"
    );
}

#[test]
fn require_timestamp_writes_nothing_instead() {
    let dir = TempDir::new("require");
    let document_path = document(&dir);

    let output = cli()
        .args([
            "--soft-key",
            "--tsa",
            "custom",
            "--tsa-url",
            DEAD_TSA,
            "--require-timestamp",
            "sign",
        ])
        .arg(&document_path)
        .output()
        .expect("the CLI failed to start");

    assert!(
        !output.status.success(),
        "--require-timestamp must fail when the timestamp cannot be had"
    );
    assert!(
        !dir.join("document.txt.asc").exists(),
        "--require-timestamp must not leave a signature behind"
    );
}

#[test]
fn a_pdf_signature_survives_the_same_way() {
    let dir = TempDir::new("pdf");
    let pdf = dir.join("document.pdf");
    std::fs::write(&pdf, minimal_pdf()).unwrap();

    let output = cli()
        .args([
            "--soft-key",
            "--tsa",
            "custom",
            "--tsa-url",
            DEAD_TSA,
            "sign-pdf",
        ])
        .arg(&pdf)
        .output()
        .expect("the CLI failed to start");

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let signed = dir.join("document.pdf.signed.pdf");
    assert!(signed.exists(), "the signed PDF was thrown away");

    let verify = cli()
        .arg("verify-pdf")
        .arg(&signed)
        .output()
        .expect("the CLI failed to start");
    let json = String::from_utf8_lossy(&verify.stdout);
    assert!(
        json.contains("\"signatureVerified\": true"),
        "the PDF that was kept does not verify:\n{json}"
    );
}

/// A one page PDF, written out by hand so the test needs no fixture.
fn minimal_pdf() -> Vec<u8> {
    let body = b"%PDF-1.7\n\
        1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n\
        2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n\
        3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 595 842]>>endobj\n";
    let mut pdf = body.to_vec();
    let offsets: Vec<usize> = [&b"1 0 obj"[..], b"2 0 obj", b"3 0 obj"]
        .iter()
        .map(|marker| find(&pdf, marker).expect("marker"))
        .collect();

    let xref_start = pdf.len();
    pdf.extend_from_slice(b"xref\n0 4\n0000000000 65535 f \n");
    for offset in offsets {
        pdf.extend_from_slice(format!("{offset:010} 00000 n \n").as_bytes());
    }
    pdf.extend_from_slice(
        format!("trailer<</Size 4/Root 1 0 R>>\nstartxref\n{xref_start}\n%%EOF").as_bytes(),
    );
    pdf
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}
