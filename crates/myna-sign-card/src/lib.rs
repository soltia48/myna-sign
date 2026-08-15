//! The card side of myna-sign.
//!
//! Everything that touches a reader lives here, and nothing else does. `myna-sign-core` knows only
//! [`myna_sign_core::DigestSigner`]; this crate is the one implementation of it that involves
//! hardware, plus the session handling that goes with a card whose state outlives the process.
//!
//! # The security status outlives your program
//!
//! `myna-card` says it plainly and it bears repeating, because it decides the shape of this
//! module: a successful VERIFY stays in effect until the card leaves the field. Dropping the
//! connection does not clear it. Reconnecting does not clear it. A fresh process is not a fresh
//! card — only powering the card down is.
//!
//! So [`CardSession`] powers the card down when it is finished with, in [`CardSession::close`] and
//! again in `Drop` for the paths that do not get there. Without that, closing the application
//! leaves the signature key unlocked for whatever talks to the card next.
//!
//! Powering down closes the window at the end. [`Sharing::Exclusive`] closes it in the middle: a
//! shared connection leaves the unlocked key reachable by anything else on the machine for as long
//! as the session lasts, and that is the whole time between the password and the signature. A
//! session that will present a password takes the card to itself; one that only reads does not,
//! because reserving a card nobody is signing with locks out software somebody may be relying on.
//!
//! # Retry counters
//!
//! The signature password allows five attempts, and a blocked key can only be unblocked at a
//! municipal office. [`CardSession::sign_pin_retries`] asks the card how many are left without
//! spending one, and [`CardSession::unlock`] refuses to present a password to a key that is
//! already blocked rather than confirming the bad news at the user's expense.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use myna_card::ap::jpki::{JpkiAp, SignatureScheme, TokenType};
use myna_card::transport::pcsc::{self, PcscTransport};
// The PC/SC crate itself, aliased so `pcsc` keeps meaning myna-card's module everywhere below.
use ::pcsc as pcsc_crate;
use myna_card::{Card, Certificate, Pin, Retries};
use myna_sign_core::error::{Error, Result};
use myna_sign_core::signer::DigestSigner;
use myna_sign_core::x509::CertificateInfo;
use serde::Serialize;
use zeroize::Zeroize;

pub use myna_card::transport::pcsc::Sharing;

/// The readers the PC/SC service knows about.
pub fn list_readers() -> Result<Vec<String>> {
    Ok(pcsc::list_readers()?)
}

/// Whether this error is another program holding the card.
///
/// Worth telling apart from every other PC/SC failure because it is the one the person at the
/// keyboard can act on — close the other software, try again — and because it is the expected
/// answer rather than a fault: asking for the card to yourself is asking something that can
/// reasonably be refused.
///
/// A predicate rather than an error variant of its own so that the `pcsc` crate stays inside this
/// module. Callers match on the answer, not on a message.
pub fn is_card_busy(error: &Error) -> bool {
    matches!(
        error,
        Error::Card(myna_card::Error::Pcsc(pcsc_crate::Error::SharingViolation))
    )
}

/// What the card says about itself before anything is presented to it.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CardStatus {
    /// The reader it is in.
    pub reader: String,
    /// `JPKIAPICCTOKEN2` for a plastic card, or one of the phone tokens.
    pub token_type: String,
    /// Whether this is the card rather than the スマホ用電子証明書.
    pub physical_card: bool,
    /// Whether a 署名用証明書 is present.
    ///
    /// It is optional — it is not issued to children under fifteen — so an application that is
    /// about to ask for a signature password can find out first whether there is anything to sign
    /// with.
    pub has_sign_certificate: bool,
    /// Whether a 利用者証明用証明書 is present.
    pub has_auth_certificate: bool,
    /// Attempts left on the signature password, or `None` if the card would not say.
    pub sign_pin_retries: Option<u8>,
    /// Attempts left on the authentication PIN.
    pub auth_pin_retries: Option<u8>,
}

/// A connection to a card.
#[derive(Debug)]
pub struct CardSession {
    card: Card<PcscTransport>,
    reader: String,
    sign_certificate: Option<Certificate>,
    sign_ca_certificate: Option<Certificate>,
    closed: bool,
}

impl CardSession {
    /// Connect to a card.
    ///
    /// `reader` names one, or the first available is used. `sharing` says whether anything else may
    /// hold the card meanwhile: [`Sharing::Exclusive`] for a session that will present the
    /// signature password, [`Sharing::Shared`] for one that only reads.
    ///
    /// # Errors
    ///
    /// [`is_card_busy`] is true of the error when `sharing` is [`Sharing::Exclusive`] and something
    /// else already has the card.
    pub fn connect(reader: Option<&str>, sharing: Sharing) -> Result<Self> {
        let (card, reader) = match reader {
            Some(name) => (pcsc::connect(name, sharing)?, name.to_owned()),
            None => {
                let name = pcsc::list_readers()?
                    .into_iter()
                    .next()
                    .ok_or(myna_card::Error::NoReader)?;
                (pcsc::connect(&name, sharing)?, name)
            }
        };
        Ok(CardSession {
            card,
            reader,
            sign_certificate: None,
            sign_ca_certificate: None,
            closed: false,
        })
    }

    /// The reader this session is on.
    pub fn reader(&self) -> &str {
        &self.reader
    }

    /// Read what the card will say without a password.
    pub fn status(&mut self) -> Result<CardStatus> {
        let mut jpki = JpkiAp::select(&mut self.card)?;
        let token_type = jpki.read_token_type()?;
        let availability = jpki.read_certificate_availability()?;
        // Asking for the counters costs nothing: JICSAP 6.4.9 (5) defines an empty VERIFY as
        // reporting the remaining attempts without consuming one.
        let sign_pin_retries = jpki.sign_pin_retries().ok().and_then(Retries::count);
        let auth_pin_retries = jpki.auth_pin_retries().ok().and_then(Retries::count);

        Ok(CardStatus {
            reader: self.reader.clone(),
            token_type: token_type.name().to_owned(),
            physical_card: matches!(token_type, TokenType::Card),
            has_sign_certificate: availability.has_sign_certificate(),
            has_auth_certificate: availability.has_auth_certificate(),
            sign_pin_retries,
            auth_pin_retries,
        })
    }

    /// The 利用者証明用証明書, which needs no password.
    ///
    /// Useful for showing that a card is present and readable before asking for anything. It
    /// carries no 基本4情報 — that is the other certificate.
    pub fn auth_certificate(&mut self) -> Result<CertificateInfo> {
        let mut jpki = JpkiAp::select(&mut self.card)?;
        CertificateInfo::read(&jpki.read_auth_certificate()?)
    }

    /// Attempts left on the signature password, without spending one.
    pub fn sign_pin_retries(&mut self) -> Result<Retries> {
        let mut jpki = JpkiAp::select(&mut self.card)?;
        Ok(jpki.sign_pin_retries()?)
    }

    /// Present the signature password and read the 署名用証明書.
    ///
    /// The password is consumed and zeroed. The certificate is kept for the rest of the session so
    /// that signing does not have to ask again.
    ///
    /// # Errors
    ///
    /// [`Error::Card`] wrapping [`myna_card::Error::PinBlocked`] if the key is already blocked —
    /// checked *before* presenting anything, so a blocked key does not cost the caller an attempt
    /// to discover.
    ///
    /// # Warning
    ///
    /// **The 署名用証明書 carries the holder's 氏名, 住所, 生年月日 and 性別.** Anything that
    /// displays or writes out the result is disclosing them.
    pub fn unlock(&mut self, password: &mut String) -> Result<CertificateInfo> {
        let pin = Pin::new(password.as_bytes());
        password.zeroize();
        let pin = pin?;

        if let Retries::Blocked = self.sign_pin_retries()? {
            return Err(Error::Card(myna_card::Error::PinBlocked));
        }

        let mut jpki = JpkiAp::select(&mut self.card)?;
        jpki.verify_sign_pin(&pin)?;

        let certificate = jpki.read_sign_certificate()?;
        // The CA above it, so that a signature can carry a chain a verifier can walk without
        // having the card. Not fatal if it will not read: the signature is still valid, and a
        // verifier can reach a J-LIS root without it.
        self.sign_ca_certificate = jpki.read_sign_ca_certificate().ok();

        let info = CertificateInfo::read(&certificate)?;
        self.sign_certificate = Some(certificate);
        Ok(info)
    }

    /// Whether the signature password has been presented in this session.
    pub fn unlocked(&self) -> bool {
        self.sign_certificate.is_some()
    }

    /// A signer for the 署名用秘密鍵.
    ///
    /// # Errors
    ///
    /// [`Error::NotChecked`] if [`CardSession::unlock`] has not run — the certificate the signer
    /// has to show is itself behind the password.
    pub fn signer(&mut self) -> Result<CardSigner<'_>> {
        let certificate = self.sign_certificate.clone().ok_or_else(|| {
            Error::NotChecked("the signature password has not been presented".into())
        })?;
        Ok(CardSigner {
            session: self,
            certificate,
        })
    }

    /// The CA certificate above the 署名用証明書, DER, once the session is unlocked.
    ///
    /// Goes into a CMS structure as an extra certificate so a verifier can build the chain.
    pub fn sign_ca_certificate_der(&self) -> Option<Vec<u8>> {
        self.sign_ca_certificate.as_ref().map(|c| c.der().to_vec())
    }

    /// Power the card down and disconnect.
    ///
    /// This is the only thing that clears the security status. Call it; do not rely on the process
    /// exiting.
    pub fn close(mut self) -> Result<()> {
        self.power_down()
    }

    fn power_down(&mut self) -> Result<()> {
        if self.closed {
            return Ok(());
        }
        self.closed = true;
        self.sign_certificate = None;
        self.sign_ca_certificate = None;
        self.card.transport_mut().power_cycle()?;
        Ok(())
    }
}

impl Drop for CardSession {
    /// A last resort, not the intended path.
    ///
    /// [`CardSession::close`] reports whether the card actually powered down; this cannot, and a
    /// failure here leaves the signature key unlocked with nobody told. It is here so that an
    /// early return or a panic does not leave the card open, not so that callers can ignore
    /// `close`.
    fn drop(&mut self) {
        let _ = self.power_down();
    }
}

/// The 署名用秘密鍵, as something `myna-sign-core` can sign with.
#[derive(Debug)]
pub struct CardSigner<'a> {
    session: &'a mut CardSession,
    certificate: Certificate,
}

impl DigestSigner for CardSigner<'_> {
    fn certificate(&self) -> &Certificate {
        &self.certificate
    }

    /// Sign with `CLA 80 INS 2A`, P1 = 02.
    ///
    /// `PreHashedDigestInfo` is the only scheme that fits: the digest here is over bytes the core
    /// assembled — an OpenPGP trailer, or a set of CMS attributes — not over a file the card could
    /// hash for itself, and the card's hash-on-card modes cap the input at what a short APDU
    /// carries anyway.
    fn sign_sha256(&mut self, digest: &[u8; 32]) -> Result<Vec<u8>> {
        // Re-selecting the application does not clear its security status (JICSAP 5.1.3 rule 2),
        // so this is free and keeps the session from having to hold a borrow between signatures.
        let mut jpki = JpkiAp::select(&mut self.session.card)?;
        Ok(jpki.sign_with_sign_key(SignatureScheme::PreHashedDigestInfo, digest)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The card layer cannot be exercised without a card; what can be checked here is that the
    /// types line up, so a change to `DigestSigner` breaks the build rather than the card.
    #[test]
    fn the_card_signer_is_a_digest_signer() {
        fn assert_impl<T: DigestSigner>() {}
        assert_impl::<CardSigner<'_>>();
    }

    #[test]
    fn listing_readers_does_not_panic_without_a_reader() {
        // On a machine with no pcscd this is an error, not a crash, and the interface has to be
        // able to show it.
        match list_readers() {
            Ok(readers) => println!("{} reader(s)", readers.len()),
            Err(e) => println!("no readers: {e}"),
        }
    }
}
