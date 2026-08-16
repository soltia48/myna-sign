//! A command line front end for `myna-sign-core`.
//!
//! Not the product — the GUI is — but the way to exercise the whole pipeline against a real card
//! without a window, and the way CI produces files for `gpg`, `pdfsig` and `openssl ts` to judge.
//!
//! `--soft-key` swaps the card for a software key, so every subcommand can be run on a machine
//! with no reader. That key is generated on the spot and thrown away; it signs nothing anyone
//! should rely on, and the program says so.

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand, ValueEnum};
use myna_sign_card::Sharing;
use myna_sign_core::error::{Error, Result};
use myna_sign_core::openpgp::{self, SignOptions};
use myna_sign_core::pdf;
use myna_sign_core::signer::DigestSigner;
use myna_sign_core::time::Timestamp;
use myna_sign_core::tsa::{self, BlockingHttp, TsaConfig, TsaPreset};

#[derive(Parser)]
#[command(
    name = "myna-sign",
    about = "Sign files and PDFs with a My Number Card"
)]
struct Cli {
    /// Use a throwaway software key instead of a card.
    ///
    /// For testing the pipeline where there is no reader. The signatures it makes are worthless.
    #[arg(long, global = true)]
    soft_key: bool,

    /// Which reader to use. Defaults to the first one.
    #[arg(long, global = true)]
    reader: Option<String>,

    /// Where to get a timestamp.
    #[arg(long, global = true, default_value = "none")]
    tsa: TsaChoice,

    /// A custom timestamp authority, used when `--tsa custom`.
    #[arg(long, global = true)]
    tsa_url: Option<String>,

    /// A PEM trust anchor for a custom timestamp authority.
    #[arg(long, global = true)]
    tsa_root: Option<PathBuf>,

    /// Fail rather than write a signature whose timestamp could not be obtained.
    ///
    /// Without it, an unreachable authority is a warning: the signature is written without a
    /// timestamp, because the card has already made it and throwing that away helps nobody. With
    /// it, nothing is written — for a pipeline that needs the timestamp or nothing.
    #[arg(long, global = true)]
    require_timestamp: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Clone, Copy, ValueEnum)]
enum TsaChoice {
    /// Do not timestamp. Nothing leaves the machine.
    None,
    /// <https://freetsa.org/tsr>.
    Freetsa,
    /// <http://timestamp.digicert.com>.
    Digicert,
    /// The authority named by `--tsa-url`.
    Custom,
}

#[derive(Subcommand)]
enum Command {
    /// List the PC/SC readers.
    Readers,
    /// Show what the card says without a password.
    Card,
    /// Sign files, producing detached OpenPGP signatures.
    Sign {
        /// The files to sign.
        #[arg(required = true)]
        files: Vec<PathBuf>,
        /// Leave the signer's certificate out of the signature.
        ///
        /// The certificate carries the holder's 氏名, 住所, 生年月日 and 性別; embedding it
        /// publishes them. Without it, whoever verifies needs the certificate by other means.
        #[arg(long)]
        no_certificate: bool,
        /// Also write the OpenPGP public key, so `gpg` can verify.
        #[arg(long)]
        public_key: bool,
        /// Produce a cleartext signed message instead of a detached signature.
        ///
        /// The text and the signature end up in one readable file, which cannot be separated from
        /// what it signs. Trailing whitespace is not signable and is removed.
        #[arg(long)]
        cleartext: bool,
        /// Also write the RFC 3161 token on its own, as `<file>.tsr`.
        ///
        /// The token is already inside the signature; this is for checking it with
        /// `openssl ts -verify`.
        #[arg(long)]
        tsr: bool,
    },
    /// Sign a PDF.
    SignPdf {
        /// The PDF to sign.
        file: PathBuf,
        /// Where to write it. Defaults to `<file>.signed.pdf`.
        #[arg(long)]
        out: Option<PathBuf>,
        /// Why it was signed.
        #[arg(long)]
        reason: Option<String>,
        /// Where it was signed.
        #[arg(long)]
        location: Option<String>,
        /// An image to draw in the signature field.
        ///
        /// Without one, a panel is drawn: who signed, when, and why. Pass `--invisible` for a
        /// signature that does not appear on the page at all.
        #[arg(long)]
        image: Option<PathBuf>,
        /// Sign without anything appearing on the page.
        #[arg(long, conflicts_with = "image")]
        invisible: bool,
        /// Which page the signature appears on.
        #[arg(long, default_value_t = 1)]
        page: usize,
        /// `x1,y1,x2,y2` in PDF user space, origin at the bottom left.
        ///
        /// Left out, a generated panel is placed at the bottom right of the page at its own
        /// proportions, and a supplied image is placed there too.
        #[arg(long)]
        rect: Option<String>,
    },
    /// Verify a detached OpenPGP signature.
    Verify {
        /// The `.asc`.
        signature: PathBuf,
        /// The document it covers.
        ///
        /// Not needed for a cleartext signed message, which carries the text it signs.
        document: Option<PathBuf>,
        /// Accept the JPKI test hierarchy. A test card is not a person's card.
        #[arg(long)]
        accept_test_hierarchy: bool,
    },
    /// Verify the signatures in a PDF.
    VerifyPdf {
        /// The PDF.
        file: PathBuf,
        /// Accept the JPKI test hierarchy.
        #[arg(long)]
        accept_test_hierarchy: bool,
    },
    /// Ask a timestamp authority for a token over a file, and check what comes back.
    TsaProbe,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(&cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: &Cli) -> Result<()> {
    match &cli.command {
        Command::Readers => {
            for reader in myna_sign_card::list_readers()? {
                println!("{reader}");
            }
            Ok(())
        }
        Command::Card => {
            // Reads only, so it shares: a command for looking at the card should not be able to
            // evict whatever else is using it.
            let mut session =
                myna_sign_card::CardSession::connect(cli.reader.as_deref(), Sharing::Shared)?;
            let status = session.status()?;
            println!("{}", serde_json::to_string_pretty(&status).unwrap());
            if status.has_auth_certificate {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&session.auth_certificate()?).unwrap()
                );
            }
            session.close()
        }
        Command::Sign {
            files,
            no_certificate,
            public_key,
            cleartext,
            tsr,
        } => with_signer(cli, |signer, ca| {
            let _ = ca;
            let options = SignOptions {
                embed_certificate: !no_certificate,
                created: Some(Timestamp::now()?),
            };
            for file in files {
                let mut signature = if *cleartext {
                    let text = std::fs::read_to_string(file)
                        .map_err(|e| Error::io(format!("reading {} as text", file.display()), e))?;
                    openpgp::sign_cleartext(signer, &text, &options)?
                } else {
                    openpgp::sign_detached(
                        signer,
                        std::fs::File::open(file)
                            .map_err(|e| Error::io(format!("opening {}", file.display()), e))?,
                        &options,
                    )?
                };

                let value = signature.signature_value()?;
                timestamp_or_warn(cli, &value, &mut |token| signature.attach_timestamp(token))?;

                let out = with_suffix(file, "asc");
                write(&out, &signature.armored)?;
                println!("{}", out.display());

                if *tsr {
                    match openpgp::embedded_timestamp(&signature.signature) {
                        Some(token) => {
                            let out = with_suffix(file, "tsr");
                            write(&out, token)?;
                            println!("{}", out.display());
                        }
                        None => {
                            eprintln!(
                                "note: --tsr was asked for but there is no timestamp to write"
                            )
                        }
                    }
                }
            }
            if *public_key {
                let name = myna_sign_core::x509::CertificateInfo::read(signer.certificate())?
                    .common_name
                    .unwrap_or_else(|| "My Number Card".into());
                let armored = openpgp::export_certificate(signer, &name)?;
                let out = with_suffix(&files[0], "pubkey.asc");
                write(&out, &armored)?;
                println!("{}", out.display());
            }
            Ok(())
        }),
        Command::SignPdf {
            file,
            out,
            reason,
            location,
            image,
            invisible,
            page,
            rect,
        } => with_signer(cli, |signer, ca| {
            let original = std::fs::read(file)
                .map_err(|e| Error::io(format!("reading {}", file.display()), e))?;

            // What goes on the page: a supplied image, a generated panel, or nothing.
            let drawn = if *invisible {
                None
            } else if let Some(path) = image {
                Some(pdf::SignatureImage::from_bytes(
                    std::fs::read(path)
                        .map_err(|e| Error::io(format!("reading {}", path.display()), e))?,
                ))
            } else {
                let certificate =
                    myna_sign_core::x509::CertificateInfo::read(signer.certificate())?;
                Some(pdf::SignatureBlock::describe(&certificate, Timestamp::now()?).render()?)
            };

            let appearance = match drawn {
                None => None,
                Some(drawn) => Some(match rect {
                    Some(rect) => pdf::Appearance {
                        page: *page,
                        rect: parse_rect(rect)?,
                        image: Some(drawn),
                    },
                    None => pdf::default_placement(&original, *page, &drawn)?,
                }),
            };

            let options = pdf::PdfSignOptions {
                reason: reason.clone(),
                location: location.clone(),
                appearance,
                extra_certificates: ca.into_iter().collect(),
                ..Default::default()
            };

            let mut signed = pdf::sign(signer, &original, &options)?;
            let value = signed.signature_value.clone();
            timestamp_or_warn(cli, &value, &mut |token| signed.attach_timestamp(token))?;

            let out = out
                .clone()
                .unwrap_or_else(|| with_suffix(file, "signed.pdf"));
            write(&out, &signed.bytes)?;
            println!("{}", out.display());
            Ok(())
        }),
        Command::Verify {
            signature,
            document,
            accept_test_hierarchy,
        } => {
            let armored = std::fs::read(signature)
                .map_err(|e| Error::io(format!("reading {}", signature.display()), e))?;
            let options = openpgp::VerifyOptions {
                certificate: None,
                accept_test_hierarchy: *accept_test_hierarchy,
            };

            // A cleartext message carries the text with it, so there is no separate document to
            // point at — recognise it rather than making the user pick a different subcommand.
            let result = if armored.starts_with(b"-----BEGIN PGP SIGNED MESSAGE-----") {
                openpgp::verify_cleartext(&armored, &options)?
            } else {
                let document = document.as_ref().ok_or_else(|| {
                    Error::malformed(
                        "a detached signature needs the document it covers as a second argument",
                    )
                })?;
                let file = std::fs::File::open(document)
                    .map_err(|e| Error::io(format!("opening {}", document.display()), e))?;
                openpgp::verify_detached(&armored, file, &options)?
            };
            println!("{}", serde_json::to_string_pretty(&result).unwrap());
            Ok(())
        }
        Command::VerifyPdf {
            file,
            accept_test_hierarchy,
        } => {
            let bytes = std::fs::read(file)
                .map_err(|e| Error::io(format!("reading {}", file.display()), e))?;
            let results = pdf::verify(
                &bytes,
                &pdf::verify::VerifyOptions {
                    accept_test_hierarchy: *accept_test_hierarchy,
                    timestamp_anchors: None,
                },
            )?;
            if results.is_empty() {
                println!("the document carries no signature");
            }
            println!("{}", serde_json::to_string_pretty(&results).unwrap());
            Ok(())
        }
        Command::TsaProbe => {
            let config = cli.tsa_config()?;
            let url = config
                .url()
                .ok_or_else(|| Error::malformed("pass --tsa to name an authority"))?;
            // Something to timestamp that is not a real signature.
            let token = tsa::fetch(&BlockingHttp::default(), url, b"myna-sign probe")?;
            let result = tsa::verify_token_with(&token, b"myna-sign probe", &config.anchors()?)?;
            println!("{}", serde_json::to_string_pretty(&result).unwrap());
            Ok(())
        }
    }
}

/// Fetch a timestamp and attach it, or say why not.
///
/// By the time this runs the card has already signed. Losing that because an authority was
/// unreachable would cost a password entry and a card operation for a reason that has nothing to do
/// with the signature, so the default is to write the signature and warn. `--require-timestamp`
/// turns the warning into a refusal, and then nothing is written.
fn timestamp_or_warn(
    cli: &Cli,
    signature_value: &[u8],
    attach: &mut dyn FnMut(&[u8]) -> Result<()>,
) -> Result<()> {
    let config = cli.tsa_config()?;
    let Some(url) = config.url() else {
        return Ok(());
    };

    match tsa::fetch(&BlockingHttp::default(), url, signature_value) {
        Ok(token) => attach(&token),
        Err(e) if cli.require_timestamp => Err(e),
        Err(e) => {
            eprintln!(
                "warning: could not get a timestamp from {url} ({e}).\n\
                 The signature was made and is being written without one; it will not be \n\
                 verifiable once the certificate expires. Pass --require-timestamp to refuse \n\
                 instead of writing."
            );
            Ok(())
        }
    }
}

impl Cli {
    fn tsa_config(&self) -> Result<TsaConfig> {
        Ok(match self.tsa {
            TsaChoice::None => TsaConfig::None,
            TsaChoice::Freetsa => TsaConfig::Preset {
                preset: TsaPreset::FreeTsa,
            },
            TsaChoice::Digicert => TsaConfig::Preset {
                preset: TsaPreset::DigiCert,
            },
            TsaChoice::Custom => {
                let url = self
                    .tsa_url
                    .clone()
                    .ok_or_else(|| Error::malformed("--tsa custom needs --tsa-url"))?;
                let root_pem = match &self.tsa_root {
                    Some(path) => Some(
                        std::fs::read_to_string(path)
                            .map_err(|e| Error::io(format!("reading {}", path.display()), e))?,
                    ),
                    None => None,
                };
                TsaConfig::Custom { url, root_pem }
            }
        })
    }
}

/// Run `body` with a signer: the card, or a throwaway software key.
///
/// The second argument is the CA certificate above the signer, when there is one to carry.
fn with_signer<F>(cli: &Cli, body: F) -> Result<()>
where
    F: FnOnce(&mut dyn DigestSigner, Option<Vec<u8>>) -> Result<()>,
{
    if cli.soft_key {
        eprintln!(
            "warning: --soft-key signs with a throwaway software key. \
             The result proves nothing about anybody."
        );
        let mut signer = myna_sign_core::signer::SoftSigner::generate(
            "CN=myna-sign soft key,C=JP",
            Timestamp::now()?,
            365,
        )?;
        return body(&mut signer, None);
    }

    // Exclusive: this session presents the signature password, and the security status that
    // creates is reachable by anything else holding the card until it is powered down.
    let mut session =
        myna_sign_card::CardSession::connect(cli.reader.as_deref(), Sharing::Exclusive)?;
    let status = session.status()?;
    if !status.has_sign_certificate {
        return Err(Error::NotChecked(
            "this card carries no 署名用証明書, so there is nothing to sign with".into(),
        ));
    }
    match status.sign_pin_retries {
        Some(0) => {
            return Err(Error::Card(myna_card::Error::PinBlocked));
        }
        Some(1) => eprintln!(
            "warning: one attempt remains on the signature password. \
             A wrong value blocks the key, and only a municipal office can unblock it."
        ),
        _ => {}
    }

    let mut password = prompt_password(status.sign_pin_retries)?;
    let certificate = session.unlock(&mut password)?;
    eprintln!(
        "signing as {} (certificate {}…)",
        certificate.common_name.as_deref().unwrap_or("<no CN>"),
        &certificate.fingerprint[..16]
    );

    let ca = session.sign_ca_certificate_der();
    let result = {
        let mut signer = session.signer()?;
        body(&mut signer, ca)
    };
    // Powering the card down is what clears the security status; a failure here is worth saying
    // out loud, because the key stays unlocked until the card leaves the field.
    if let Err(e) = session.close() {
        eprintln!(
            "warning: the card did not power down ({e}); the signature key may still be unlocked"
        );
    }
    result
}

/// Read the signature password without echoing it.
///
/// Falls back to a plain read when there is no terminal, which is the case in a pipeline; the
/// warning says so rather than silently echoing.
fn prompt_password(retries: Option<u8>) -> Result<String> {
    match retries {
        Some(n) => eprint!("署名用パスワード ({n} attempt(s) remaining): "),
        None => eprint!("署名用パスワード: "),
    }
    std::io::stderr().flush().ok();

    // Read with the terminal's echo turned off. Reading from stdin the ordinary way puts the
    // password on the screen and leaves it in the scrollback of a terminal that outlives the
    // process — for a PIN that five wrong tries send to a municipal office, that is not acceptable.
    let password = rpassword::read_password().map_err(|e| Error::io("reading the password", e))?;
    eprintln!();
    Ok(password.trim_end_matches(['\r', '\n']).to_owned())
}

fn parse_rect(text: &str) -> Result<[f32; 4]> {
    let parts: Vec<&str> = text.split(',').map(str::trim).collect();
    if parts.len() != 4 {
        return Err(Error::malformed("--rect wants four numbers: x1,y1,x2,y2"));
    }
    let mut out = [0.0f32; 4];
    for (slot, part) in out.iter_mut().zip(parts) {
        *slot = part
            .parse()
            .map_err(|_| Error::malformed(format!("{part:?} is not a number")))?;
    }
    Ok(out)
}

fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(".");
    name.push(suffix);
    path.with_file_name(name)
}

fn write(path: &Path, bytes: &[u8]) -> Result<()> {
    std::fs::write(path, bytes).map_err(|e| Error::io(format!("writing {}", path.display()), e))
}
