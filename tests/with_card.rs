//! Checks that need a real card in a real reader.
//!
//! Ignored by default and gated on an environment variable, because they need hardware and because
//! the second one presents the signature password — which has five attempts before the key is
//! blocked and only a municipal office can unblock it.
//!
//! ```sh
//! MYNA_SIGN_TEST_PASSWORD=... cargo test --test with_card -- --ignored --test-threads=1
//! ```
//!
//! The password is read from the environment rather than taken as an argument so that it does not
//! appear in a process listing.

use myna_card::ap::jpki::JpkiAp;
use myna_card::{Card, transport::pcsc};
// `pcsc` above is myna-card's module; the leading `::` is what reaches the crate of that name.
use ::pcsc as pcsc_crate;
use myna_sign::card::{CardSession, Sharing};

/// The password, or `None` to skip.
fn password() -> Option<String> {
    std::env::var("MYNA_SIGN_TEST_PASSWORD")
        .ok()
        .filter(|p| !p.is_empty())
}

#[test]
#[ignore = "needs a card in a reader"]
fn reads_what_the_card_says_without_a_password() {
    let mut session = CardSession::connect(None, Sharing::Shared).expect("no card");
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

    session
        .close()
        .expect("the master-file state was not selected");
}

/// The check the design calls out as needing hardware on every platform.
///
/// A successful VERIFY survives dropping and reopening a connection. Selecting a different
/// application clears the status of the one left, though, and `CardSession::close` uses the MF
/// selection added in myna-card 3.1 for exactly that.
///
/// So: unlock, confirm the protected file reads, select the MF state, confirm it no longer does.
#[test]
#[ignore = "needs a card in a reader, and presents the password"]
fn selecting_the_mf_clears_the_security_status() {
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

    let mut card = pcsc::connect_any(Sharing::Shared).expect("no card");
    assert!(
        !sign_certificate_readable(&mut card),
        "the 署名用証明書 read before any password was presented — the card was already unlocked, \
         so this test cannot tell whether selecting the MF clears anything. Remove the card from the \
         reader, put it back, and run again."
    );
    drop(card);

    {
        let mut session = CardSession::connect(None, Sharing::Exclusive).expect("no card");
        session
            .unlock(&mut password)
            .expect("the password was refused");
        assert!(session.unlocked());
        // Leaving the scope without `close` would still select the MF through `Drop`; being
        // explicit is what the application does, and it is what is under test.
        session
            .close()
            .expect("the master-file state was not selected");
    }

    let mut card = pcsc::connect_any(Sharing::Shared).expect("the card went away");
    assert!(
        !sign_certificate_readable(&mut card),
        "the 署名用証明書 still reads after selecting the MF: the security status survived, and \
         closing the application would leave the signature key unlocked"
    );
}

/// One password entry, several signatures.
///
/// The application signs a batch on a single unlock; this is the claim that makes that safe to do.
#[test]
#[ignore = "needs a card in a reader, and presents the password"]
fn one_unlock_signs_more_than_once() {
    use myna_sign::signer::{DigestSigner as _, sha256};

    let Some(mut password) = password() else {
        eprintln!("skipping: set MYNA_SIGN_TEST_PASSWORD to run this");
        return;
    };

    let mut session = CardSession::connect(None, Sharing::Exclusive).expect("no card");
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

    session
        .close()
        .expect("the master-file state was not selected");
}

/// An exclusive session actually keeps other connections out.
///
/// The one thing about `Sharing::Exclusive` that cannot be established without hardware. Everything
/// below the API is the PC/SC service's behaviour, and a mode that silently did nothing would look
/// exactly like a mode that worked — right up until another program signed with a key this
/// application had unlocked.
///
/// No password, so this one costs nothing to run.
#[test]
#[ignore = "needs a card in a reader"]
fn an_exclusive_session_locks_other_connections_out() {
    let session = CardSession::connect(None, Sharing::Exclusive).expect("no card");

    let refused = pcsc::connect_any(Sharing::Shared);
    assert!(
        matches!(
            refused,
            Err(myna_card::Error::Pcsc(pcsc_crate::Error::SharingViolation))
        ),
        "a second connection was allowed while an exclusive session was open: {refused:?}"
    );

    // And the card is usable again once the reservation is given up.
    session
        .close()
        .expect("the master-file state was not selected");
    pcsc::connect_any(Sharing::Shared).expect("the card stayed locked after close");
}
