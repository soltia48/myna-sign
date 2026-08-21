//! Signing, verification, and card access for myna-sign.
//!
//! The signing formats know about the Individual Number Card only through
//! [`signer::DigestSigner`]: something that turns a 32 byte SHA-256 digest into a 256 byte
//! PKCS #1 v1.5 signature and can show the X.509 certificate the key belongs to. Reader and card
//! session handling stay isolated in [`card`].
//!
//! That is deliberate. The card's signing command is the one part of the system that cannot be
//! exercised without hardware, so it is kept to a single method behind a trait. Everything else —
//! OpenPGP, CMS, PDF, RFC 3161 — is built and tested against [`signer::SoftSigner`], a software
//! key, and does not change when a real card is plugged in.
//!
//! # Layout
//!
//! - [`card`] — PC/SC reader access and the hardware signer.
//! - [`signer`] — the signer trait and the software key used by tests and the CLI's `--soft-key`.
//! - [`x509`] — the JPKI certificate: what is in it, and checking it to a J-LIS root.
//! - [`time`] — the clock, kept in one place because signatures record time in four formats.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod card;
pub mod cms;
pub mod crypto;
pub mod error;
pub mod openpgp;
pub mod pdf;
pub mod signer;
pub mod time;
pub mod tsa;
pub mod x509;

pub use error::{Error, Result};
pub use signer::DigestSigner;

/// The X.509 certificate type used throughout, re-exported from `myna-card`.
///
/// This is the `x509-cert` 0.3 world. The CMS code re-parses the same DER with `x509-cert` 0.2.
pub use myna_card::Certificate;
