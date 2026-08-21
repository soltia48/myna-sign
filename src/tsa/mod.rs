//! RFC 3161 timestamps.
//!
//! # Why the program bothers
//!
//! A JPKI signing certificate is good for at most five years, and stops being good the moment the
//! holder moves house or changes their name. Without a timestamp, a signature becomes unverifiable
//! when that happens: there is no way to show it was made while the certificate was still valid.
//! A timestamp token from a third party fixes the signature to an instant, and verification then
//! asks whether the certificate was valid *then* — see [`crate::x509::ReferenceDate`].
//!
//! # What is timestamped
//!
//! Not the document. The token is computed over the **signature value** — `signerInfo.signature`
//! for CMS, the RSA MPI for OpenPGP — which is what RFC 3161 §3.3 and PAdES both do. It says "this
//! signature existed at this time", which is the claim that matters; the signature already binds
//! the document.
//!
//! Only 32 bytes leave the machine. The authority sees a SHA-256 hash and nothing else — not the
//! document, not the signature, not the signer. That is worth saying out loud in the interface,
//! because "send it to a server on the internet" is otherwise a reasonable thing to be wary of.
//!
//! # What is not done here
//!
//! No network. [`build_request`] and [`Request::parse_response`] are the protocol;
//! [`HttpPost`] is the hole where a transport goes, so that this module can be tested against
//! recorded responses and so that a caller can use whatever HTTP client it already has. A blocking
//! client is provided behind the `tsa-http` feature.

pub mod roots;

use der::asn1::{Any, Int, OctetString};
use der::{Decode, Encode};
use serde::{Deserialize, Serialize};
use x509_tsp::{MessageImprint, TimeStampReq, TimeStampResp, TspVersion, TstInfo};

use crate::cms;
use crate::error::{Error, Result};
use crate::signer::sha256;
use crate::time::Timestamp;

pub use roots::{ChainOutcome, TrustAnchors};

/// Where to get a timestamp.
///
/// `rename_all_fields` is not decoration: `rename_all` renames the *variants* only, so without it
/// `root_pem` stays `root_pem` on the wire while every caller that speaks camelCase sends
/// `rootPem`. Combined with `serde(default)` below, that means a trust anchor someone pasted in
/// would be dropped in silence and the authority checked against the Mozilla list instead.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub enum TsaConfig {
    /// Do not timestamp. The default: nothing leaves the machine unless it was asked for.
    #[default]
    None,
    /// One of the authorities this program knows about.
    Preset {
        /// Which one.
        preset: TsaPreset,
    },
    /// Somewhere else.
    Custom {
        /// The endpoint.
        url: String,
        /// A PEM trust anchor for the authority, when it is not one the Mozilla root list covers.
        #[serde(default)]
        root_pem: Option<String>,
    },
}

impl TsaConfig {
    /// The endpoint to post to, or `None` when timestamping is off.
    pub fn url(&self) -> Option<&str> {
        match self {
            TsaConfig::None => None,
            TsaConfig::Preset { preset } => Some(preset.url()),
            TsaConfig::Custom { url, .. } => Some(url),
        }
    }

    /// The trust anchors to check the authority's certificate against.
    pub fn anchors(&self) -> Result<TrustAnchors> {
        match self {
            TsaConfig::None => Ok(TrustAnchors::default()),
            TsaConfig::Preset { preset } => Ok(preset.anchors()),
            TsaConfig::Custom { root_pem, .. } => {
                let mut anchors = TrustAnchors::mozilla();
                if let Some(pem) = root_pem {
                    anchors.add_pem(pem)?;
                }
                Ok(anchors)
            }
        }
    }
}

/// The authorities this program ships an endpoint for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum TsaPreset {
    /// <https://freetsa.org/tsr>. Free, and anchored at its own root, which no browser or OS
    /// carries — so this program carries it (see [`roots::FREETSA_ROOT`]).
    FreeTsa,
    /// <http://timestamp.digicert.com>. Anchored in the Mozilla root list.
    DigiCert,
}

impl TsaPreset {
    /// The endpoint.
    pub fn url(self) -> &'static str {
        match self {
            TsaPreset::FreeTsa => "https://freetsa.org/tsr",
            TsaPreset::DigiCert => "http://timestamp.digicert.com",
        }
    }

    /// The anchors that authority's certificates chain to.
    pub fn anchors(self) -> TrustAnchors {
        match self {
            // FreeTSA's root is self-signed and in no public store. Carried, like the J-LIS roots.
            TsaPreset::FreeTsa => TrustAnchors::freetsa(),
            TsaPreset::DigiCert => TrustAnchors::mozilla(),
        }
    }

    /// A name for the interface.
    pub fn label(self) -> &'static str {
        match self {
            TsaPreset::FreeTsa => "FreeTSA",
            TsaPreset::DigiCert => "DigiCert",
        }
    }
}

// --- The protocol -----------------------------------------------------------------------------

/// A request, and what has to be checked against the response.
pub struct Request {
    /// The DER to post.
    pub der: Vec<u8>,
    imprint: [u8; 32],
    nonce: Vec<u8>,
}

/// Build a timestamp request over `signature_value`.
///
/// The nonce is fresh for every request and is checked when the response comes back; without it a
/// recorded response could be replayed to make an old signature look new.
pub fn build_request(signature_value: &[u8]) -> Result<Request> {
    let imprint = sha256(signature_value);

    let mut nonce = [0u8; 8];
    use rand::RngCore as _;
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    // `Int` is signed; keep the value positive so the encoding does not grow a leading zero and
    // so an authority that echoes the integer rather than the bytes still compares equal.
    nonce[0] &= 0x7F;
    // A leading zero byte would be stripped by the DER encoder, so avoid one.
    if nonce[0] == 0 {
        nonce[0] = 1;
    }

    let request = TimeStampReq {
        version: TspVersion::V1,
        message_imprint: MessageImprint {
            hash_algorithm: to_any_params(cms::sha256_algorithm())?,
            hashed_message: OctetString::new(imprint.as_slice())
                .map_err(|e| Error::der("message imprint", e))?,
        },
        req_policy: None,
        nonce: Some(Int::new(&nonce).map_err(|e| Error::der("nonce", e))?),
        // Ask for the authority's certificate, so the token can be verified on its own later.
        cert_req: true,
        extensions: None,
    };

    Ok(Request {
        der: request
            .to_der()
            .map_err(|e| Error::der("timestamp request", e))?,
        imprint,
        nonce: nonce.to_vec(),
    })
}

/// `x509-tsp` types the hash algorithm as `AlgorithmIdentifier<Any>`; `cms` hands out
/// `AlgorithmIdentifier<Any>` too, but from a different `der` re-export path, so it is rebuilt.
fn to_any_params(
    algorithm: spki::AlgorithmIdentifierOwned,
) -> Result<spki::AlgorithmIdentifier<Any>> {
    Ok(spki::AlgorithmIdentifier {
        oid: algorithm.oid,
        parameters: algorithm.parameters,
    })
}

/// The content type an RFC 3161 request is posted as.
pub const REQUEST_CONTENT_TYPE: &str = "application/timestamp-query";

impl Request {
    /// Read a response and hand back the timestamp token, DER.
    ///
    /// Checks the status and the nonce. The imprint inside the token is checked by
    /// [`verify_token`], which also runs for tokens loaded from a file later.
    pub fn parse_response(&self, der: &[u8]) -> Result<Vec<u8>> {
        let response =
            TimeStampResp::from_der(der).map_err(|e| Error::der("timestamp response", e))?;

        // 0 granted, 1 grantedWithMods. Anything else is a refusal.
        let status = response.status.status;
        let granted = matches!(
            status,
            cmpv2::status::PkiStatus::Accepted | cmpv2::status::PkiStatus::GrantedWithMods
        );
        if !granted {
            return Err(Error::malformed(format!(
                "the timestamp authority refused the request: status {status:?}"
            )));
        }

        let token = response.time_stamp_token.ok_or_else(|| {
            Error::malformed("the response granted the request but carried no token")
        })?;
        let token_der = token
            .to_der()
            .map_err(|e| Error::der("re-encoding the token", e))?;

        let info = tst_info(&token_der)?;
        match info.nonce.as_ref() {
            Some(n) if n.as_bytes() == self.nonce.as_slice() => {}
            Some(_) => {
                return Err(Error::SignatureInvalid(
                    "the timestamp echoes a different nonce, so it is not a reply to this request"
                        .into(),
                ));
            }
            None => {
                return Err(Error::SignatureInvalid(
                    "the timestamp echoes no nonce, so it cannot be tied to this request".into(),
                ));
            }
        }
        if info.message_imprint.hashed_message.as_bytes() != self.imprint {
            return Err(Error::SignatureInvalid(
                "the timestamp is over a different imprint than the one requested".into(),
            ));
        }

        Ok(token_der)
    }

    /// The imprint that was sent — 32 bytes, and the only thing the authority learns.
    pub fn imprint(&self) -> &[u8; 32] {
        &self.imprint
    }
}

/// The `TSTInfo` inside a token.
pub fn tst_info(token_der: &[u8]) -> Result<TstInfo> {
    let (content_type, content) = cms::encapsulated_content(token_der)?;
    if content_type != cms::ID_CT_TST_INFO {
        return Err(Error::malformed(format!(
            "the token encapsulates {content_type}, not a TSTInfo"
        )));
    }
    TstInfo::from_der(&content).map_err(|e| Error::der("TSTInfo", e))
}

// --- Verifying --------------------------------------------------------------------------------

/// What a timestamp token turned out to say.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TimestampVerification {
    /// Everything below held: the token is over this signature, it is signed by a key that is
    /// allowed to timestamp, and that key chains to an anchor.
    pub verified: bool,
    /// The token's imprint is the SHA-256 of the signature it was checked against.
    pub imprint_matches: bool,
    /// The token's own CMS signature verifies.
    pub signature_verified: bool,
    /// The responder's certificate carries a critical `extendedKeyUsage` of `timeStamping`.
    ///
    /// RFC 3161 §2.3 requires it. Without the check, any certificate the same authority issued
    /// would do, which defeats the point of having a dedicated responder key.
    pub timestamping_eku: bool,
    /// How far the responder's certificate was chained.
    pub chain: ChainOutcome,
    /// The time the authority attests to, RFC 3339.
    pub gen_time: String,
    /// The same instant, as a Unix timestamp — used as the reference date for the signer's own
    /// certificate.
    pub gen_time_unix: i64,
    /// The authority's policy OID.
    pub policy: String,
    /// The authority's name, when the token carries one.
    pub tsa_name: Option<String>,
    /// The token's serial number, hex.
    pub serial_number: String,
    /// The accuracy the authority claims, in seconds, when it states one.
    pub accuracy_seconds: Option<u64>,
}

/// Check a timestamp token against the signature it should cover.
///
/// `signature_value` is `signerInfo.signature` for a PDF, or the RSA MPI for an OpenPGP signature.
pub fn verify_token(token_der: &[u8], signature_value: &[u8]) -> Result<TimestampVerification> {
    verify_token_with(token_der, signature_value, &TrustAnchors::all())
}

/// As [`verify_token`], with the trust anchors named.
pub fn verify_token_with(
    token_der: &[u8],
    signature_value: &[u8],
    anchors: &TrustAnchors,
) -> Result<TimestampVerification> {
    let info = tst_info(token_der)?;
    let (_, econtent) = cms::encapsulated_content(token_der)?;
    let cms_result = cms::verify_signed_data(token_der, &econtent)?;

    let imprint_matches = info.message_imprint.hashed_message.as_bytes() == sha256(signature_value);
    let signature_verified = cms_result.signature_verified && cms_result.message_digest_matches;
    let timestamping_eku = cms::has_critical_timestamping_eku(&cms_result.signer_certificate)?;

    let gen_time_unix = info.gen_time.to_unix_duration().as_secs() as i64;
    let chain = roots::verify_chain(
        &cms_result.signer_certificate,
        &cms_result.certificates,
        anchors,
        Timestamp::from_unix_seconds(gen_time_unix),
    );

    Ok(TimestampVerification {
        verified: imprint_matches && signature_verified && timestamping_eku && chain.verified,
        imprint_matches,
        signature_verified,
        timestamping_eku,
        chain,
        gen_time: Timestamp::from_unix_seconds(gen_time_unix).to_rfc3339(),
        gen_time_unix,
        policy: info.policy.to_string(),
        tsa_name: info.tsa.as_ref().map(|n| format!("{n:?}")),
        serial_number: hex::encode_upper(info.serial_number.as_bytes()),
        accuracy_seconds: info.accuracy.as_ref().and_then(|a| a.seconds),
    })
}

// --- Transport --------------------------------------------------------------------------------

/// The hole where an HTTP client goes.
///
/// This module has no network code of its own so that it can be tested against recorded responses
/// and so that an application can use the client it already has. `tsa-http` provides one.
pub trait HttpPost {
    /// POST `body` with `content_type` and return the response body.
    fn post(&self, url: &str, content_type: &str, body: &[u8]) -> Result<Vec<u8>>;
}

/// Fetch a timestamp over `signature_value`.
pub fn fetch(http: &dyn HttpPost, url: &str, signature_value: &[u8]) -> Result<Vec<u8>> {
    let request = build_request(signature_value)?;
    let response = http.post(url, REQUEST_CONTENT_TYPE, &request.der)?;
    request.parse_response(&response)
}

/// A blocking HTTP client, for callers that do not have one.
#[cfg(feature = "tsa-http")]
pub struct BlockingHttp {
    agent: ureq::Agent,
}

#[cfg(feature = "tsa-http")]
impl BlockingHttp {
    /// A client with the given overall timeout.
    pub fn new(timeout: std::time::Duration) -> Self {
        let config = ureq::Agent::config_builder()
            .timeout_global(Some(timeout))
            .build();
        BlockingHttp {
            agent: config.into(),
        }
    }
}

#[cfg(feature = "tsa-http")]
impl Default for BlockingHttp {
    fn default() -> Self {
        // Long enough for a slow authority, short enough that a signature waiting on one does not
        // look like a hang.
        BlockingHttp::new(std::time::Duration::from_secs(15))
    }
}

#[cfg(feature = "tsa-http")]
impl HttpPost for BlockingHttp {
    fn post(&self, url: &str, content_type: &str, body: &[u8]) -> Result<Vec<u8>> {
        let mut response = self
            .agent
            .post(url)
            .header("Content-Type", content_type)
            .send(body)
            .map_err(|e| {
                Error::io(
                    format!("posting to {url}"),
                    std::io::Error::other(e.to_string()),
                )
            })?;
        response.body_mut().read_to_vec().map_err(|e| {
            Error::io(
                format!("reading the reply from {url}"),
                std::io::Error::other(e.to_string()),
            )
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_request_carries_a_positive_nonce_and_asks_for_the_certificate() {
        let request = build_request(b"a signature").unwrap();
        let decoded = TimeStampReq::from_der(&request.der).unwrap();
        assert_eq!(decoded.version, TspVersion::V1);
        assert!(
            decoded.cert_req,
            "without certReq the token cannot stand alone"
        );
        assert_eq!(
            decoded.message_imprint.hashed_message.as_bytes(),
            sha256(b"a signature")
        );
        let nonce = decoded.nonce.unwrap();
        assert_eq!(nonce.as_bytes(), request.nonce.as_slice());
        assert!(
            nonce.as_bytes()[0] < 0x80,
            "the nonce must encode as positive"
        );
    }

    #[test]
    fn two_requests_do_not_share_a_nonce() {
        let a = build_request(b"x").unwrap();
        let b = build_request(b"x").unwrap();
        assert_ne!(a.nonce, b.nonce);
    }

    #[test]
    fn a_custom_authority_keeps_its_trust_anchor_through_json() {
        // The field name is the whole point of this test. A `root_pem` on the wire and a `rootPem`
        // from the interface are not the same key, and `serde(default)` makes the mismatch silent:
        // the anchor vanishes and the authority is checked against the Mozilla list instead.
        let config = TsaConfig::Custom {
            url: "https://tsa.example/tsr".into(),
            root_pem: Some("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n".into()),
        };
        let json = serde_json::to_string(&config).unwrap();
        assert!(
            json.contains("\"rootPem\""),
            "the interface sends rootPem: {json}"
        );
        assert_eq!(serde_json::from_str::<TsaConfig>(&json).unwrap(), config);

        // And what the window actually posts, spelled out rather than round-tripped, so this still
        // fails if both sides drift the same way.
        let from_window: TsaConfig = serde_json::from_str(
            r#"{"kind":"custom","url":"https://tsa.example/tsr","rootPem":"anchor"}"#,
        )
        .unwrap();
        assert_eq!(
            from_window,
            TsaConfig::Custom {
                url: "https://tsa.example/tsr".into(),
                root_pem: Some("anchor".into()),
            }
        );
    }

    #[test]
    fn the_imprint_is_the_hash_of_the_signature_and_nothing_else() {
        // The document never reaches the authority. This is the test that says so.
        let request = build_request(b"signature value").unwrap();
        assert_eq!(request.imprint(), &sha256(b"signature value"));
        assert!(
            request.der.len() < 128,
            "a request is tiny: {} bytes",
            request.der.len()
        );
    }
}
