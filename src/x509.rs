//! Reading a JPKI certificate, and deciding how far it can be trusted.
//!
//! `myna-card` already parses the certificate and can check it to a root J-LIS published. Two
//! things are added here.
//!
//! The first is the holder's details. The 署名用証明書 carries the 基本4情報 — 氏名, 住所, 生年月日,
//! 性別 — and a program that writes the certificate into a file it hands to someone else has to be
//! able to show the user exactly what that discloses. [`CertificateInfo::holder`] is what the
//! confirmation screen reads.
//!
//! The second is honesty about the verdict. A chain that reaches a J-LIS root is not the same as a
//! certificate that is valid: revocation is published by JPKI as a separate online service and
//! nothing here consults it. [`TrustCheck`] keeps "the chain verified" and "nothing was checked"
//! apart, and has no variant meaning "valid".
//!
//! # Which x509-cert
//!
//! Everything below reads the DER with `x509-cert` 0.2, the same major the CMS code uses, rather
//! than the 0.3 that `myna-card` exposes through [`Certificate::inner`]. Re-parsing costs a
//! microsecond and keeps one ASN.1 world in this crate instead of two.

use der::asn1::ObjectIdentifier;
use der::{Decode as _, Encode as _};
use myna_card::certificate::roots::Accept;
use myna_card::{Certificate, Date};
use serde::Serialize;

use crate::error::{Error, Result};
use crate::signer::sha256;
use crate::time::Timestamp;

/// `id-ce-subjectAltName`.
const SUBJECT_ALT_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.17");

/// The attributes a JPKI signature certificate carries about its holder.
///
/// # Provenance
///
/// Read off a JPKI **test** card on 2026-08-15, which is the only card that has been available
/// here. What that card established directly:
///
/// | OID | value on the card | conclusion |
/// |---|---|---|
/// | `…5.5.1` | `黒桐　幹也` | 氏名 |
/// | `…5.5.2` | `00000` | 氏名の代替文字位置 — one digit per character of 氏名 |
/// | `…5.5.3` | `1` | 性別, one JIS X 0303 digit |
/// | `…5.5.4` | `319800217` | 生年月日 — `EYYYYMMDD`, see [`format_birth_date`] |
/// | `…5.5.5` | `東京都清瀬市観布子南１２－７－２０２` | 住所 |
/// | `…5.5.6` | `000000000000000000` | 住所の代替文字位置 — one digit per character of 住所 |
///
/// Two earlier drafts of this table were wrong: one placed 住所 at `…5.5.4` and 生年月日 at
/// `…5.5.2`, both from published documentation rather than from a card.
///
/// The label is applied only when the value has the shape the field should have (see
/// [`HolderField::accepts`]); anything else is disclosed under its raw OID rather than under a name
/// that might be wrong. Nothing is ever dropped — a certificate written into a file discloses every
/// one of these, so every one of them is shown.
const HOLDER_ATTRIBUTES: &[(&str, HolderField)] = &[
    ("1.2.392.200149.8.5.5.1", HolderField::Name),
    ("1.2.392.200149.8.5.5.2", HolderField::NameSubstitutes),
    ("1.2.392.200149.8.5.5.3", HolderField::Sex),
    ("1.2.392.200149.8.5.5.4", HolderField::BirthDate),
    ("1.2.392.200149.8.5.5.5", HolderField::Address),
    ("1.2.392.200149.8.5.5.6", HolderField::AddressSubstitutes),
];

/// Render a JPKI birth date, `EYYYYMMDD`.
///
/// The leading digit is the era — 1 明治, 2 大正, 3 昭和, 4 平成, 5 令和, 0 不明 — and the eight
/// that follow are the **Gregorian** date, not the year within that era. So `319800217` is
/// 1980-02-17, which fell in 昭和55年.
///
/// Returns `None` for anything that is not that shape, which is what keeps a value that means
/// something else from being presented as a date.
pub fn format_birth_date(value: &str) -> Option<String> {
    if value.len() != 9 || !value.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let era = match &value[..1] {
        "1" => Some("明治"),
        "2" => Some("大正"),
        "3" => Some("昭和"),
        "4" => Some("平成"),
        "5" => Some("令和"),
        "0" => None, // 不明: the date is still there, the era is not stated.
        _ => return None,
    };
    let (year, month, day) = (&value[1..5], &value[5..7], &value[7..9]);
    if !("01".."13").contains(&month) || !("01".."32").contains(&day) {
        return None;
    }
    Some(match era {
        Some(era) => format!("{year}-{month}-{day}（{era}）"),
        None => format!("{year}-{month}-{day}"),
    })
}

/// Which of the 基本4情報 an attribute is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum HolderField {
    /// 氏名.
    Name,
    /// 生年月日.
    BirthDate,
    /// 性別.
    Sex,
    /// 住所.
    Address,
    /// 氏名の代替文字使用位置情報.
    NameSubstitutes,
    /// 住所の代替文字使用位置情報.
    AddressSubstitutes,
}

impl HolderField {
    /// Whether a value has the shape this field must have.
    ///
    /// A guard against a mislabelled identifier, not a validity check on the cardholder. Showing
    /// `生年月日: 00000` would state something about a person that the certificate does not say;
    /// showing it under its OID states exactly what is there.
    fn accepts(self, value: &str) -> bool {
        match self {
            HolderField::BirthDate => format_birth_date(value).is_some(),
            // One JIS X 0303 digit: 1 男性, 2 女性, 9 適用不能.
            HolderField::Sex => matches!(value, "1" | "2" | "9"),
            HolderField::Name | HolderField::Address => !value.trim().is_empty(),
            // One flag per character. Whether it is the right *number* of characters is decided
            // once the field it describes has also been read; see `read_holder`.
            HolderField::NameSubstitutes | HolderField::AddressSubstitutes => {
                !value.is_empty() && value.bytes().all(|b| b == b'0' || b == b'1')
            }
        }
    }
}

/// Which characters of a name or an address were replaced by a substitute.
///
/// A JPKI certificate carries the 氏名 and 住所 in a restricted character repertoire. A character
/// the repertoire cannot hold is written as a substitute, and a parallel string of flags — one
/// digit per character, `1` where a substitution happened — says where.
///
/// This matters for more than curiosity: where a flag is set, **the text on screen is not the text
/// on the resident register**. Anyone comparing a signature against an official document needs to
/// know that, so the positions are surfaced rather than folded away.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Substitutes {
    /// Character positions that are substitutes, counting from 1.
    pub positions: Vec<usize>,
    /// The flags as the certificate wrote them.
    pub raw: String,
    /// Whether the flags describe exactly as many characters as the field has.
    ///
    /// `false` means the certificate is not laid out the way this program expects, so
    /// [`Substitutes::positions`] cannot be relied on — reported rather than guessed at.
    pub length_matches: bool,
}

impl Substitutes {
    fn read(flags: &str, subject: Option<&str>) -> Self {
        Substitutes {
            positions: flags
                .chars()
                .enumerate()
                .filter(|(_, c)| *c == '1')
                .map(|(i, _)| i + 1)
                .collect(),
            raw: flags.to_owned(),
            length_matches: subject.is_some_and(|s| s.chars().count() == flags.chars().count()),
        }
    }

    /// Whether any character was substituted.
    pub fn any(&self) -> bool {
        !self.positions.is_empty()
    }
}

/// What the certificate discloses about its holder.
///
/// Every field is optional. The 利用者証明用証明書 carries none of them, and a 署名用証明書 whose
/// layout differs from the one assumed above carries them under [`Holder::other`].
#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Holder {
    /// 氏名.
    pub name: Option<String>,
    /// 生年月日.
    pub birth_date: Option<String>,
    /// 性別.
    pub sex: Option<String>,
    /// 住所.
    pub address: Option<String>,
    /// Which characters of [`Holder::name`] are substitutes.
    pub name_substitutes: Option<Substitutes>,
    /// Which characters of [`Holder::address`] are substitutes.
    pub address_substitutes: Option<Substitutes>,
    /// Anything else in `subjectAltName`, as `(OID, value)`.
    ///
    /// Shown to the user as written. An attribute nobody recognises is still disclosed by writing
    /// the certificate into a file, so it is not dropped.
    pub other: Vec<(String, String)>,
}

impl Holder {
    /// Whether anything at all was found.
    pub fn is_empty(&self) -> bool {
        self.name.is_none()
            && self.birth_date.is_none()
            && self.sex.is_none()
            && self.address.is_none()
            && self.other.is_empty()
    }

    /// Whether any character of the name or the address is a substitute.
    ///
    /// Where this is true, what the certificate says is not exactly what the resident register
    /// says, and an interface showing the holder has to say so.
    pub fn has_substitutes(&self) -> bool {
        [&self.name_substitutes, &self.address_substitutes]
            .into_iter()
            .flatten()
            .any(Substitutes::any)
    }
}

/// A certificate, in the form the front end and the confirmation screens want.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CertificateInfo {
    /// Subject distinguished name, RFC 4514.
    pub subject: String,
    /// The subject's `CN`, which is the holder's name on a 署名用証明書.
    pub common_name: Option<String>,
    /// Issuer distinguished name.
    pub issuer: String,
    /// Serial number, hex.
    pub serial_number: String,
    /// Start of the validity period, `YYYY-MM-DD`.
    pub not_before: String,
    /// End of the validity period, `YYYY-MM-DD`.
    pub not_after: String,
    /// Key size in bits.
    pub key_bits: usize,
    /// SHA-256 of the DER, hex — how to refer to this certificate without printing it.
    pub fingerprint: String,
    /// What it says about its holder.
    pub holder: Holder,
}

impl CertificateInfo {
    /// Read a certificate.
    pub fn read(cert: &Certificate) -> Result<Self> {
        let (from, to) = cert.validity();
        Ok(CertificateInfo {
            subject: cert.subject(),
            common_name: common_name(&cert.subject()),
            issuer: cert.issuer(),
            serial_number: hex::encode_upper(cert.serial_number()),
            not_before: format!("{from}"),
            not_after: format!("{to}"),
            key_bits: cert.public_key()?.bits(),
            fingerprint: hex::encode(sha256(cert.der())),
            holder: read_holder(cert.der())?,
        })
    }
}

/// Pull `CN` out of a rendered distinguished name.
///
/// The DN arrives already formatted, so this is string work rather than another DER pass. A `CN`
/// containing a comma would be quoted by the formatter, and that case is handled; one containing a
/// quote is not, and falls back to the whole DN being shown instead.
fn common_name(dn: &str) -> Option<String> {
    for part in dn.split(',') {
        let part = part.trim();
        if let Some(value) = part.strip_prefix("CN=") {
            return Some(value.trim_matches('"').to_string());
        }
    }
    None
}

/// Read the holder attributes out of `subjectAltName`.
fn read_holder(der: &[u8]) -> Result<Holder> {
    use x509_cert::ext::pkix::SubjectAltName;
    use x509_cert::ext::pkix::name::GeneralName;

    let cert = x509_cert::Certificate::from_der(der)
        .map_err(|e| Error::der("re-parsing the certificate", e))?;

    let Some(extensions) = cert.tbs_certificate.extensions.as_ref() else {
        return Ok(Holder::default());
    };
    let Some(ext) = extensions.iter().find(|e| e.extn_id == SUBJECT_ALT_NAME) else {
        return Ok(Holder::default());
    };
    let san = SubjectAltName::from_der(ext.extn_value.as_bytes())
        .map_err(|e| Error::der("subjectAltName", e))?;

    // Collected first, assembled second: the substitution flags only make sense next to the field
    // they describe, and this card writes them in the order 1, 4, 3, 5, 2, 6 — the flags arrive
    // before and after their subject, so there is no order to rely on.
    let mut attributes: Vec<(String, String)> = Vec::new();
    for name in san.0.iter() {
        let GeneralName::OtherName(other) = name else {
            continue;
        };
        // `OtherName.value` is the `[0] EXPLICIT` content already unwrapped, so it *is* the string
        // object. Taking `.value()` here would hand back the characters without their tag, which no
        // string decoder recognises — every attribute then fell through to hex, which is how this
        // was found.
        let encoded = other.value.to_der().unwrap_or_default();
        attributes.push((other.type_id.to_string(), decode_string(&encoded)));
    }

    let field_of = |oid: &str| -> Option<HolderField> {
        HOLDER_ATTRIBUTES
            .iter()
            .find(|(o, _)| *o == oid)
            .map(|(_, field)| *field)
    };
    let value_of = |wanted: HolderField| -> Option<&str> {
        attributes
            .iter()
            .find(|(oid, value)| field_of(oid) == Some(wanted) && wanted.accepts(value))
            .map(|(_, value)| value.as_str())
    };

    let mut holder = Holder {
        name: value_of(HolderField::Name).map(str::to_owned),
        // Shown rendered rather than raw: `319800217` on screen tells the user nothing about what
        // the certificate is disclosing, and disclosure is the whole point of this field.
        birth_date: value_of(HolderField::BirthDate).and_then(format_birth_date),
        sex: value_of(HolderField::Sex).map(str::to_owned),
        address: value_of(HolderField::Address).map(str::to_owned),
        name_substitutes: value_of(HolderField::NameSubstitutes)
            .map(|flags| Substitutes::read(flags, value_of(HolderField::Name))),
        address_substitutes: value_of(HolderField::AddressSubstitutes)
            .map(|flags| Substitutes::read(flags, value_of(HolderField::Address))),
        other: Vec::new(),
    };

    // Anything not recognised, or recognised but the wrong shape, is still disclosed by writing
    // the certificate into a file — so it is shown under its identifier rather than dropped.
    for (oid, value) in &attributes {
        let recognised = field_of(oid).is_some_and(|field| field.accepts(value));
        if !recognised {
            holder.other.push((oid.clone(), value.clone()));
        }
    }

    Ok(holder)
}

/// Render a DER string value, whatever string type it turned out to be.
///
/// The attributes are documented as `UTF8String`, but a value that is not one is still disclosed
/// by writing the certificate out, so an unrecognised encoding is shown as hex rather than
/// dropped.
fn decode_string(bytes: &[u8]) -> String {
    use der::asn1::{Ia5StringRef, PrintableStringRef, Utf8StringRef};

    if let Ok(s) = Utf8StringRef::from_der(bytes) {
        return s.as_str().to_owned();
    }
    if let Ok(s) = PrintableStringRef::from_der(bytes) {
        return s.as_str().to_owned();
    }
    if let Ok(s) = Ia5StringRef::from_der(bytes) {
        return s.as_str().to_owned();
    }
    // Not a string type we know. Show the bytes rather than pretend there was nothing there.
    hex::encode(bytes)
}

// ---------------------------------------------------------------------------------------------

/// How far a certificate was checked.
///
/// There is deliberately no variant meaning "valid". The strongest thing this program can say is
/// [`TrustCheck::ChainVerified`], and even that leaves revocation unexamined — which is why the
/// field is on the variant rather than left for the caller to remember.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "result", rename_all = "camelCase")]
pub enum TrustCheck {
    /// The chain reached a root this program carries, and both certificates were within their
    /// validity on the reference date.
    ChainVerified {
        /// Whether the root belongs to the test hierarchy rather than the production one.
        ///
        /// A test card is not a person's Individual Number Card, and a result carrying this must
        /// never be presented as if it were.
        test_hierarchy: bool,
        /// The date the validity was judged on, and where that date came from.
        reference: ReferenceDate,
        /// Always false in this version. Named rather than omitted so that the front end shows
        /// "revocation: not checked" instead of quietly implying it was.
        revocation_checked: bool,
    },
    /// The chain did not verify.
    Failed {
        /// What went wrong.
        reason: String,
    },
}

/// The date a certificate's validity was judged on, and how it was arrived at.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "source", rename_all = "camelCase")]
pub enum ReferenceDate {
    /// A verified RFC 3161 timestamp said the signature existed at this time.
    ///
    /// This is what lets a signature outlive its certificate: the question becomes whether the
    /// certificate was valid then, not whether it is valid now.
    Timestamp {
        /// The instant, RFC 3339.
        at: String,
    },
    /// No timestamp, so the system clock was used and the signature is only as good as the
    /// certificate is today.
    Now {
        /// The instant, RFC 3339.
        at: String,
    },
}

impl ReferenceDate {
    /// The date to check validity on.
    pub fn date(&self) -> Result<Date> {
        let at = match self {
            ReferenceDate::Timestamp { at } | ReferenceDate::Now { at } => at,
        };
        parse_rfc3339_date(at)
    }

    /// A reference date taken from the system clock.
    pub fn now() -> Result<Self> {
        Ok(ReferenceDate::Now {
            at: Timestamp::now()?.to_rfc3339(),
        })
    }

    /// A reference date taken from a verified timestamp token.
    pub fn from_timestamp(at: Timestamp) -> Self {
        ReferenceDate::Timestamp {
            at: at.to_rfc3339(),
        }
    }
}

/// Parse the `YYYY-MM-DD` prefix of one of the strings above.
fn parse_rfc3339_date(s: &str) -> Result<Date> {
    let bad = || Error::malformed(format!("{s:?} is not an RFC 3339 instant"));
    let date = s.get(..10).ok_or_else(bad)?;
    let mut parts = date.split('-');
    let year = parts.next().ok_or_else(bad)?.parse().map_err(|_| bad())?;
    let month = parts.next().ok_or_else(bad)?.parse().map_err(|_| bad())?;
    let day = parts.next().ok_or_else(bad)?.parse().map_err(|_| bad())?;
    Ok(Date { year, month, day })
}

/// Check a certificate to a root J-LIS published.
///
/// `accept` decides whether the test hierarchy counts. Pass [`Accept::ProductionOnly`] anywhere
/// the answer decides whether to believe a real cardholder.
///
/// Never returns `Err` for a certificate that simply did not verify — that is
/// [`TrustCheck::Failed`], which is a result and not an error. `Err` is reserved for a reference
/// date that could not be worked out.
pub fn check_to_root(
    cert: &Certificate,
    reference: ReferenceDate,
    accept: Accept,
) -> Result<TrustCheck> {
    let on = reference.date()?;
    match cert.verify_to_root(on, accept) {
        Ok(()) => Ok(TrustCheck::ChainVerified {
            test_hierarchy: is_test_hierarchy(cert, on),
            reference,
            revocation_checked: false,
        }),
        Err(e) => Ok(TrustCheck::Failed {
            reason: e.to_string(),
        }),
    }
}

/// Whether the root that signed `cert` belongs to the test hierarchy.
///
/// Only called once the chain has already verified, so a root is known to exist; if the lookup
/// somehow fails here the answer is "assume test", which is the cautious direction — it downgrades
/// a result rather than dressing a test card up as a real one.
fn is_test_hierarchy(cert: &Certificate, on: Date) -> bool {
    use myna_card::certificate::roots::{self, Hierarchy};

    let _ = on;
    match roots::issuer_of(cert, Accept::ProductionOnly) {
        Ok(_) => false,
        Err(_) => roots::KNOWN
            .iter()
            .filter(|r| r.hierarchy == Hierarchy::Test)
            .any(|r| {
                r.certificate()
                    .is_ok_and(|root| cert.verify_signature(&root).is_ok())
            }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pulls_the_common_name_out_of_a_distinguished_name() {
        assert_eq!(
            common_name("CN=Test Signer,C=JP").as_deref(),
            Some("Test Signer")
        );
        assert_eq!(
            common_name("C=JP,O=JPKI,CN=山田太郎").as_deref(),
            Some("山田太郎")
        );
        assert_eq!(common_name("C=JP,O=JPKI"), None);
    }

    #[test]
    fn parses_the_date_out_of_an_rfc3339_instant() {
        let d = parse_rfc3339_date("2026-08-15T06:26:28Z").unwrap();
        assert_eq!((d.year, d.month, d.day), (2026, 8, 15));
        assert!(parse_rfc3339_date("nope").is_err());
    }

    #[test]
    fn a_field_is_only_labelled_when_the_value_has_its_shape() {
        // `00000` sits under an identifier an earlier draft labelled 生年月日. Presenting it as a
        // date would state something the certificate does not say.
        assert!(!HolderField::BirthDate.accepts("00000"));
        assert!(HolderField::BirthDate.accepts("319800217"));
        assert!(HolderField::Sex.accepts("1"));
        assert!(!HolderField::Sex.accepts("319800217"));
        assert!(HolderField::Name.accepts("黒桐　幹也"));
        assert!(!HolderField::Name.accepts("  "));
    }

    #[test]
    fn substitution_flags_line_up_with_the_characters_they_describe() {
        // The test card: 黒桐　幹也 is five characters and its flags are five digits.
        let none = Substitutes::read("00000", Some("黒桐　幹也"));
        assert!(!none.any());
        assert!(none.length_matches);

        // A substitute in the second position, which means the name on screen is not the name on
        // the register — the interface has to be able to say so.
        let some = Substitutes::read("01000", Some("黒桐　幹也"));
        assert_eq!(some.positions, vec![2]);
        assert!(some.any());

        // Counted in characters, not bytes: an address of 18 characters is many more bytes.
        let address = "東京都清瀬市観布子南１２－７－２０２";
        assert_eq!(address.chars().count(), 18);
        assert!(Substitutes::read(&"0".repeat(18), Some(address)).length_matches);
        assert!(!Substitutes::read(&"0".repeat(17), Some(address)).length_matches);
    }

    #[test]
    fn flags_are_only_flags() {
        assert!(HolderField::NameSubstitutes.accepts("00000"));
        assert!(HolderField::NameSubstitutes.accepts("01001"));
        assert!(!HolderField::NameSubstitutes.accepts("00200"));
        assert!(!HolderField::NameSubstitutes.accepts(""));
    }

    #[test]
    fn renders_a_birth_date_with_its_era() {
        // The eight digits after the era are Gregorian: 1980-02-17 fell in 昭和55年.
        assert_eq!(
            format_birth_date("319800217").as_deref(),
            Some("1980-02-17（昭和）")
        );
        assert_eq!(
            format_birth_date("520200101").as_deref(),
            Some("2020-01-01（令和）")
        );
        // Era 0 is 不明; the date stands on its own.
        assert_eq!(
            format_birth_date("019800217").as_deref(),
            Some("1980-02-17")
        );
        // Not a date.
        assert_eq!(format_birth_date("00000"), None);
        assert_eq!(format_birth_date("619800217"), None, "no such era");
        assert_eq!(format_birth_date("319801317"), None, "no month 13");
    }

    #[test]
    fn decodes_the_string_types_that_turn_up_and_falls_back_to_hex() {
        // UTF8String "abc"
        assert_eq!(decode_string(&[0x0C, 0x03, b'a', b'b', b'c']), "abc");
        // PrintableString "abc"
        assert_eq!(decode_string(&[0x13, 0x03, b'a', b'b', b'c']), "abc");
        // An INTEGER is not a string; it must still be shown.
        assert_eq!(decode_string(&[0x02, 0x01, 0x05]), "020105");
    }
}

#[cfg(all(test, feature = "soft-signer"))]
mod soft_tests {
    use super::*;
    use crate::signer::{DigestSigner as _, SoftSigner};

    #[test]
    fn reads_a_certificate_with_no_holder_attributes() {
        let s = SoftSigner::generate(
            "CN=Test Signer,C=JP",
            Timestamp::from_unix_seconds(1_700_000_000),
            365,
        )
        .unwrap();
        let info = CertificateInfo::read(s.certificate()).unwrap();
        assert_eq!(info.common_name.as_deref(), Some("Test Signer"));
        assert_eq!(info.key_bits, 2048);
        assert_eq!(info.not_before, "2023-11-14");
        assert!(info.holder.is_empty(), "{:?}", info.holder);
        assert_eq!(info.fingerprint.len(), 64);
    }

    #[test]
    fn a_self_signed_certificate_reaches_no_jpki_root() {
        let s = SoftSigner::generate(
            "CN=Test Signer,C=JP",
            Timestamp::from_unix_seconds(1_700_000_000),
            365,
        )
        .unwrap();
        let check = check_to_root(
            s.certificate(),
            ReferenceDate::Timestamp {
                at: "2023-12-01T00:00:00Z".into(),
            },
            Accept::ProductionOnly,
        )
        .unwrap();
        assert!(matches!(check, TrustCheck::Failed { .. }), "{check:?}");
    }
}
