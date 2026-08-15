//! Checks that need a real card in a real reader.
//!
//! Ignored by default and gated on an environment variable, because they need hardware and because
//! the second one presents the signature password — which has five attempts before the key is
//! blocked and only a municipal office can unblock it.
//!
//! ```sh
//! MYNA_SIGN_TEST_PASSWORD=... cargo test -p myna-sign-card -- --ignored --test-threads=1
//! ```
//!
//! The password is read from the environment rather than taken as an argument so that it does not
//! appear in a process listing.

use myna_card::ap::jpki::JpkiAp;
use myna_card::{Card, transport::pcsc};
use myna_sign_card::CardSession;

/// The password, or `None` to skip.
fn password() -> Option<String> {
    std::env::var("MYNA_SIGN_TEST_PASSWORD")
        .ok()
        .filter(|p| !p.is_empty())
}

#[test]
#[ignore = "needs a card in a reader"]
fn reads_what_the_card_says_without_a_password() {
    let mut session = CardSession::connect(None).expect("no card");
    let status = session.status().expect("cannot read the card");

    println!("{status:#?}");
    assert!(
        status.physical_card,
        "expected a plastic card, got {}",
        status.token_type
    );
    assert!(
        status.has_sign_certificate,
        "this card carries no 署名用証明書"
    );

    // Reading the status must not have spent an attempt.
    assert_eq!(
        status.sign_pin_retries,
        Some(5),
        "the counter moved just from reading the card, or the card is not fresh"
    );

    session.close().expect("the card did not power down");
}

/// The check the design calls out as needing hardware on every platform.
///
/// A successful VERIFY survives the process on this card; the only thing that clears it is powering
/// the card down. If `power_cycle` does not actually do that — and how a `Disposition` is honoured
/// is up to the driver — then closing the application leaves the signature key unlocked for
/// whatever talks to the card next, silently.
///
/// So: unlock, confirm the protected file reads, power down, confirm it no longer does.
#[test]
#[ignore = "needs a card in a reader, and presents the password"]
fn powering_the_card_down_clears_the_security_status() {
    let Some(mut password) = password() else {
        eprintln!("skipping: set MYNA_SIGN_TEST_PASSWORD to run this");
        return;
    };

    // EF 0001 is behind the signature password, so whether it reads is the observable form of
    // "is the card still unlocked".
    fn sign_certificate_readable(card: &mut Card<pcsc::PcscTransport>) -> bool {
        JpkiAp::select(card)
            .and_then(|mut jpki| jpki.read_sign_certificate_der())
            .is_ok()
    }

    let mut card = pcsc::connect_any().expect("no card");
    assert!(
        !sign_certificate_readable(&mut card),
        "the 署名用証明書 read before any password was presented — the card was already unlocked, \
         so this test cannot tell whether powering down clears anything. Remove the card from the \
         reader, put it back, and run again."
    );
    drop(card);

    {
        let mut session = CardSession::connect(None).expect("no card");
        session
            .unlock(&mut password)
            .expect("the password was refused");
        assert!(session.unlocked());
        // Leaving the scope without `close` would still power down through `Drop`; being explicit
        // is what the application does, and it is what is under test.
        session.close().expect("the card did not power down");
    }

    let mut card = pcsc::connect_any().expect("the card went away");
    assert!(
        !sign_certificate_readable(&mut card),
        "the 署名用証明書 still reads after power_cycle: the security status survived, and closing \
         the application would leave the signature key unlocked"
    );
}

/// One password entry, several signatures.
///
/// The application signs a batch on a single unlock; this is the claim that makes that safe to do.
#[test]
#[ignore = "needs a card in a reader, and presents the password"]
fn one_unlock_signs_more_than_once() {
    use myna_sign_core::signer::{DigestSigner as _, sha256};

    let Some(mut password) = password() else {
        eprintln!("skipping: set MYNA_SIGN_TEST_PASSWORD to run this");
        return;
    };

    let mut session = CardSession::connect(None).expect("no card");
    session
        .unlock(&mut password)
        .expect("the password was refused");

    let mut signer = session.signer().expect("not unlocked");
    for message in [b"first".as_slice(), b"second", b"third"] {
        // `sign_sha256_checked` verifies the result against the card's own certificate, so a
        // signature that came back wrong fails here rather than in a file someone was given.
        let signature = signer
            .sign_sha256_checked(&sha256(message))
            .expect("the card refused to sign");
        assert_eq!(signature.len(), 256);
    }

    session.close().expect("the card did not power down");
}
