//! Trust anchors for timestamp authorities, and walking a chain to one.
//!
//! The two authorities this program ships presets for need different treatment, which is worth
//! stating because it is not obvious until you look at a real token:
//!
//! - **DigiCert**'s responder chains to `DigiCert Trusted Root G4`, which is in the Mozilla root
//!   list, so [`TrustAnchors::mozilla`] covers it.
//! - **FreeTSA**'s responder chains to `O=Free TSA, OU=Root CA`, which is self-signed and in no
//!   browser or operating system store at all. It is compiled in from `assets/certs/`, the same
//!   way
//!   `myna-card` carries the J-LIS roots — a root read from disk at run time is a root an attacker
//!   can replace.
//!
//! A custom authority gets the Mozilla list plus whatever PEM the user supplies. If nothing
//! matches, the outcome is [`ChainOutcome::verified`] `== false` with a reason — never a silent
//! pass, and never a claim that the signature is bad, because the signature was not the problem.

use serde::Serialize;

use crate::cms;
use crate::error::{Error, Result};
use crate::time::Timestamp;

/// FreeTSA's root, as published at <https://freetsa.org/files/cacert.pem>.
///
/// Compiled in rather than read at run time so that nothing can substitute one.
pub const FREETSA_ROOT: &[u8] = include_bytes!("../../assets/certs/freetsa-root.cer");

/// How deep a chain may go before it is treated as a loop.
const MAX_DEPTH: usize = 8;

/// A set of trust anchors.
#[derive(Debug, Clone, Default)]
pub struct TrustAnchors {
    /// Whole certificates: the ones compiled in, and any the user supplied.
    certificates: Vec<Vec<u8>>,
    /// Whether the Mozilla root list counts.
    mozilla: bool,
}

impl TrustAnchors {
    /// No anchors at all. Nothing will verify against this.
    pub fn none() -> Self {
        TrustAnchors::default()
    }

    /// The Mozilla root list.
    pub fn mozilla() -> Self {
        TrustAnchors {
            certificates: Vec::new(),
            mozilla: true,
        }
    }

    /// FreeTSA's own root.
    pub fn freetsa() -> Self {
        TrustAnchors {
            certificates: vec![FREETSA_ROOT.to_vec()],
            mozilla: false,
        }
    }

    /// Everything this program knows: the Mozilla list and the roots it carries.
    ///
    /// Used when verifying a token that arrived in a file, where there is no configuration saying
    /// which authority it should have come from.
    pub fn all() -> Self {
        TrustAnchors {
            certificates: vec![FREETSA_ROOT.to_vec()],
            mozilla: true,
        }
    }

    /// Add anchors from a PEM bundle.
    pub fn add_pem(&mut self, pem: &str) -> Result<()> {
        let mut found = 0;
        for block in pem.split("-----BEGIN CERTIFICATE-----").skip(1) {
            let Some(body) = block.split("-----END CERTIFICATE-----").next() else {
                continue;
            };
            let base64: String = body.chars().filter(|c| !c.is_whitespace()).collect();
            use base64::Engine as _;
            let der = base64::engine::general_purpose::STANDARD
                .decode(&base64)
                .map_err(|e| Error::malformed(format!("the trust anchor is not valid PEM: {e}")))?;
            // Reject anything that is not a certificate here rather than at verification time.
            cms::subject_of(&der)?;
            self.certificates.push(der);
            found += 1;
        }
        if found == 0 {
            return Err(Error::malformed(
                "no CERTIFICATE block in the supplied trust anchor",
            ));
        }
        Ok(())
    }

    /// Whether there is anything to check against.
    pub fn is_empty(&self) -> bool {
        self.certificates.is_empty() && !self.mozilla
    }

    /// Try to anchor `certificate`: does something here vouch for it?
    ///
    /// Returns the anchor's name.
    fn anchor_for(&self, certificate_der: &[u8]) -> Option<String> {
        // The carried roots first: they are few, and a preset's own root is the expected answer.
        for root in &self.certificates {
            if cms::names_link(certificate_der, root).unwrap_or(false)
                && cms::verify_certificate_signature(certificate_der, root).is_ok()
            {
                return cms::subject_of(root).ok();
            }
        }
        if !self.mozilla {
            return None;
        }

        let issuer = cms::issuer_name_der(certificate_der).ok()?;
        for anchor in webpki_roots::TLS_SERVER_ROOTS {
            if !name_matches(anchor.subject.as_ref(), &issuer) {
                continue;
            }
            let spki = wrap_sequence(anchor.subject_public_key_info.as_ref());
            if cms::verify_certificate_signature_with_spki(certificate_der, &spki).is_ok() {
                return Some(render_name(anchor.subject.as_ref()));
            }
        }
        None
    }
}

/// Put the outer `SEQUENCE` header back on a DER value stored without one.
///
/// The Mozilla root list keeps both the subject name and the `SubjectPublicKeyInfo` as the
/// *contents* of their `SEQUENCE`, with the tag and length stripped. Everything that parses DER
/// wants the whole thing, so it is rebuilt here. If the bytes already look like a `SEQUENCE` of
/// exactly the right length they are passed through, so this stays correct if the convention ever
/// changes.
fn wrap_sequence(contents: &[u8]) -> Vec<u8> {
    if is_whole_sequence(contents) {
        return contents.to_vec();
    }

    let len = contents.len();
    let mut out = Vec::with_capacity(len + 4);
    out.push(0x30);
    if len < 0x80 {
        out.push(len as u8);
    } else if len < 0x100 {
        out.extend_from_slice(&[0x81, len as u8]);
    } else {
        out.extend_from_slice(&[0x82, (len >> 8) as u8, len as u8]);
    }
    out.extend_from_slice(contents);
    out
}

/// Compare a trust anchor's subject with a certificate's issuer name.
///
/// The Mozilla list stores the subject as the `RDNSequence` contents, without the outer `SEQUENCE`
/// header, while a certificate's issuer is the whole `Name`. Rather than depend on which
/// convention a given version uses, both are accepted.
fn name_matches(anchor_subject: &[u8], issuer_name_der: &[u8]) -> bool {
    if anchor_subject == issuer_name_der {
        return true;
    }
    // Strip the outer SEQUENCE header from the issuer name and compare the contents.
    let Some(contents) = der_contents(issuer_name_der) else {
        return false;
    };
    contents == anchor_subject
}

/// The header length and content length of a DER TLV, if it has a definite length.
fn der_header(der: &[u8]) -> Option<(usize, usize)> {
    let first = *der.get(1)?;
    if first < 0x80 {
        return Some((2, usize::from(first)));
    }
    let count = usize::from(first & 0x7F);
    if count == 0 || count > 4 {
        return None;
    }
    let bytes = der.get(2..2 + count)?;
    let length = bytes
        .iter()
        .fold(0usize, |acc, b| (acc << 8) | usize::from(*b));
    Some((2 + count, length))
}

/// The value bytes of a DER TLV.
fn der_contents(der: &[u8]) -> Option<&[u8]> {
    let (header, _) = der_header(der)?;
    der.get(header..)
}

/// Whether `der` is one complete `SEQUENCE` and nothing more.
fn is_whole_sequence(der: &[u8]) -> bool {
    if der.first() != Some(&0x30) {
        return false;
    }
    der_header(der).is_some_and(|(header, length)| header + length == der.len())
}

/// Something readable for a name we only have as DER.
fn render_name(subject: &[u8]) -> String {
    use der::Decode as _;
    match x509_cert::name::Name::from_der(&wrap_sequence(subject)) {
        Ok(name) => name.to_string(),
        Err(_) => "<unnamed trust anchor>".into(),
    }
}

/// How far a certificate chain was walked.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChainOutcome {
    /// The chain reached an anchor.
    pub verified: bool,
    /// The anchor it reached.
    pub anchor: Option<String>,
    /// Why it did not, when it did not.
    pub reason: Option<String>,
    /// The subjects walked through, leaf first.
    pub path: Vec<String>,
    /// Whether every certificate on the path was within its validity at the reference time.
    ///
    /// Reported separately from [`ChainOutcome::verified`]: a chain whose signatures are all good
    /// but which had expired is a different situation from one that does not chain at all.
    pub within_validity: bool,
}

impl ChainOutcome {
    fn failed(reason: impl Into<String>, path: Vec<String>, within_validity: bool) -> Self {
        ChainOutcome {
            verified: false,
            anchor: None,
            reason: Some(reason.into()),
            path,
            within_validity,
        }
    }
}

/// Walk from `leaf` up through `carried` to one of `anchors`.
///
/// `at` is when the chain has to have been valid — the token's `genTime` for a timestamp, so that
/// a responder certificate which has since expired still checks out.
pub fn verify_chain(
    leaf: &[u8],
    carried: &[Vec<u8>],
    anchors: &TrustAnchors,
    at: Timestamp,
) -> ChainOutcome {
    if anchors.is_empty() {
        return ChainOutcome::failed(
            "no trust anchor was configured, so nothing was checked",
            Vec::new(),
            true,
        );
    }

    let mut path = Vec::new();
    let mut current = leaf.to_vec();
    let mut within_validity = true;

    for _ in 0..MAX_DEPTH {
        path.push(cms::subject_of(&current).unwrap_or_else(|_| "<unreadable>".into()));
        within_validity &= cms::is_valid_at(&current, at).unwrap_or(false);

        if let Some(anchor) = anchors.anchor_for(&current) {
            return ChainOutcome {
                verified: true,
                anchor: Some(anchor),
                reason: None,
                path,
                within_validity,
            };
        }

        // Not anchored here: find the certificate above this one among the ones carried.
        let next = carried.iter().find(|candidate| {
            // A self-issued certificate is its own issuer by name; stepping onto it would loop.
            !cms::is_self_issued(&current).unwrap_or(false)
                && cms::names_link(&current, candidate).unwrap_or(false)
                && cms::verify_certificate_signature(&current, candidate).is_ok()
        });

        match next {
            Some(issuer) => current = issuer.clone(),
            None => {
                return ChainOutcome::failed(
                    "the chain does not reach a trust anchor this program carries",
                    path,
                    within_validity,
                );
            }
        }
    }

    ChainOutcome::failed(
        format!("the chain is longer than {MAX_DEPTH} certificates"),
        path,
        within_validity,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_freetsa_root_is_the_one_it_claims_to_be() {
        let subject = cms::subject_of(FREETSA_ROOT).unwrap();
        assert!(subject.contains("Free TSA"), "{subject}");
        assert!(cms::is_self_issued(FREETSA_ROOT).unwrap());
        // Self-signed, and this program checks that rather than assuming it.
        cms::verify_certificate_signature(FREETSA_ROOT, FREETSA_ROOT).unwrap();
    }

    #[test]
    fn no_anchors_means_nothing_was_checked_rather_than_a_failure() {
        let outcome = verify_chain(
            FREETSA_ROOT,
            &[],
            &TrustAnchors::none(),
            Timestamp::from_unix_seconds(1_700_000_000),
        );
        assert!(!outcome.verified);
        assert!(outcome.reason.unwrap().contains("nothing was checked"));
    }

    #[test]
    fn the_carried_root_anchors_itself() {
        let outcome = verify_chain(
            FREETSA_ROOT,
            &[],
            &TrustAnchors::freetsa(),
            Timestamp::from_unix_seconds(1_700_000_000),
        );
        assert!(outcome.verified, "{outcome:?}");
        assert!(outcome.within_validity);
        assert!(outcome.anchor.unwrap().contains("Free TSA"));
    }

    #[test]
    fn a_root_outside_the_set_does_not_anchor() {
        let outcome = verify_chain(
            FREETSA_ROOT,
            &[],
            &TrustAnchors::mozilla(),
            Timestamp::from_unix_seconds(1_700_000_000),
        );
        assert!(!outcome.verified);
        assert!(outcome.reason.unwrap().contains("does not reach"));
    }

    #[test]
    fn pem_anchors_are_parsed_and_bad_ones_rejected() {
        let mut anchors = TrustAnchors::none();
        assert!(anchors.add_pem("not a pem").is_err());

        use base64::Engine as _;
        let pem = format!(
            "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
            base64::engine::general_purpose::STANDARD.encode(FREETSA_ROOT)
        );
        anchors.add_pem(&pem).unwrap();
        assert!(!anchors.is_empty());
        let outcome = verify_chain(
            FREETSA_ROOT,
            &[],
            &anchors,
            Timestamp::from_unix_seconds(1_700_000_000),
        );
        assert!(outcome.verified, "{outcome:?}");
    }

    #[test]
    fn expiry_is_reported_separately_from_the_chain() {
        // The FreeTSA root runs to 2041; long before it was issued, the chain still verifies
        // cryptographically but was not yet valid.
        let outcome = verify_chain(
            FREETSA_ROOT,
            &[],
            &TrustAnchors::freetsa(),
            Timestamp::from_unix_seconds(0),
        );
        assert!(outcome.verified, "the signatures are still good");
        assert!(!outcome.within_validity, "but it was not valid in 1970");
    }
}
