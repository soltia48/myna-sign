//! Error types.

/// Alias for [`std::result::Result`] with this crate's error type.
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Anything that can go wrong signing or verifying.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The card, or the certificate handling that comes with it.
    #[error("card: {0}")]
    Card(#[from] myna_card::Error),

    /// Reading or writing a file.
    #[error("{context}: {source}")]
    Io {
        /// What was being read or written.
        context: String,
        /// The underlying error.
        source: std::io::Error,
    },

    /// DER encoding or decoding.
    #[error("DER: {0}")]
    Der(String),

    /// Input that is not shaped the way it must be.
    #[error("malformed: {0}")]
    Malformed(String),

    /// A signature did not verify.
    ///
    /// Distinct from [`Error::NotChecked`]: here something was checked and failed.
    #[error("signature verification failed: {0}")]
    SignatureInvalid(String),

    /// A check could not be performed at all — no trust anchor, no certificate, no algorithm.
    ///
    /// This is not a failure of the thing being checked, and callers must not report it as one.
    #[error("not checked: {0}")]
    NotChecked(String),

    /// The signer produced something other than a 2048 bit RSA signature.
    #[error("expected a 256 byte signature, got {0}")]
    BadSignatureLength(usize),
}

impl Error {
    /// A [`Error::Malformed`] with a formatted message.
    pub fn malformed(message: impl Into<String>) -> Self {
        Error::Malformed(message.into())
    }

    /// A [`Error::Der`] carrying whatever the `der` crate said.
    pub fn der(context: &str, e: impl std::fmt::Display) -> Self {
        Error::Der(format!("{context}: {e}"))
    }

    /// An [`Error::Io`] that says what was being touched.
    pub fn io(context: impl Into<String>, source: std::io::Error) -> Self {
        Error::Io {
            context: context.into(),
            source,
        }
    }
}
