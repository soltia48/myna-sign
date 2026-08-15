//! The myna-sign application: the commands the interface can call, and nothing else.
//!
//! There is no signing logic here. Every command is a thin wrapper over `myna-sign-core` and
//! `myna-sign-card`, which is what keeps the parts that matter testable without a window.
//!
//! # Two rules this layer exists to enforce
//!
//! **The password never becomes a long-lived value.** It arrives as a `String` over IPC, is moved
//! into the card layer, and is zeroed there. It is never stored, never logged, and never returned.
//!
//! **The card is powered down when the session ends.** A successful VERIFY survives the process,
//! so [`disconnect`] and the exit handler both power-cycle the card. Closing the window without
//! that would leave the signature key unlocked for whatever talks to the card next.

use std::sync::{Arc, Mutex};

use myna_sign_card::{CardSession, CardStatus};
use myna_sign_core::error::Error;
use myna_sign_core::openpgp::{self, SignOptions};
use myna_sign_core::pdf;
use myna_sign_core::signer::DigestSigner;
use myna_sign_core::time::Timestamp;
use myna_sign_core::tsa::{self, BlockingHttp, TimestampVerification, TsaConfig};
use myna_sign_core::x509::CertificateInfo;
use serde::{Deserialize, Serialize};
use tauri::Manager;

/// Errors as the interface sees them.
///
/// Split so the front end can react rather than pattern-match on prose: a blocked key needs a
/// different screen from a wrong password.
///
/// A timestamp that could not be fetched is deliberately **not** here. It is not a failure of the
/// signing operation — the signature exists — so it is reported as the [`Blocker`] on the signature
/// that is waiting on a decision.
#[derive(Debug, Serialize)]
#[serde(tag = "kind", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum AppError {
    /// No card, no reader, or the card refused.
    Card {
        /// What happened.
        message: String,
    },
    /// The signature password was wrong.
    PinIncorrect {
        /// Attempts left before the key is blocked.
        retries: Option<u8>,
    },
    /// The key is blocked and only a municipal office can unblock it.
    PinBlocked,
    /// No card session is open.
    ///
    /// Distinct from [`AppError::Card`] so the interface can offer to connect rather than show a
    /// message the user cannot act on.
    NotConnected,
    /// The card stopped answering and the session was dropped.
    ///
    /// Only ever produced after something else has already failed — see [`AppState::with_session`].
    /// Nothing asks the card whether it is there on a timer.
    CardRemoved,
    /// A file could not be read or written.
    ///
    /// `operation` is already Japanese and user-facing; `detail` is the operating system's message,
    /// kept because it names the real cause — a full disk and a missing directory need different
    /// answers from the person reading it.
    Io {
        /// What was being attempted, phrased as the interface will show it.
        operation: String,
        /// What the operating system said.
        detail: String,
    },
    /// A file was asked to be signed as cleartext but is not UTF-8 text.
    NotText {
        /// The file.
        path: String,
    },
    /// Anything else.
    Failed {
        /// What happened.
        message: String,
    },
}

impl From<Error> for AppError {
    /// The kind comes from the variant and never from the message.
    ///
    /// Matching on prose would make the wording load-bearing, and it is not: every one of these
    /// strings exists to be read by a person and reworded when it reads badly.
    fn from(error: Error) -> Self {
        match &error {
            Error::Card(myna_card::Error::PinIncorrect { retries }) => {
                AppError::PinIncorrect { retries: *retries }
            }
            Error::Card(myna_card::Error::PinBlocked) => AppError::PinBlocked,
            Error::Card(_) => AppError::Card {
                message: error.to_string(),
            },
            // `Error::Io` deliberately does not become `AppError::Io`. Its context is English, and
            // it covers the timestamp POST as much as it covers files, whereas `AppError::Io`
            // promises a sentence about a file the user named. Those are built at the call sites
            // below, which are the only places that know which file it was.
            _ => AppError::Failed {
                message: error.to_string(),
            },
        }
    }
}

type Result<T> = std::result::Result<T, AppError>;

/// The last component of a path, which is what a person calls the file.
///
/// The whole path is on screen elsewhere; a sentence about a failure only reads as a sentence with
/// the name alone in it.
fn file_label(path: &str) -> String {
    std::path::Path::new(path)
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.to_owned())
}

/// A file that would not read.
fn read_error(path: &str, e: std::io::Error) -> AppError {
    AppError::Io {
        operation: format!("{} の読み込み", file_label(path)),
        detail: e.to_string(),
    }
}

/// A file that would not write.
fn write_error(path: &str, e: std::io::Error) -> AppError {
    AppError::Io {
        operation: format!("{} の書き出し", file_label(path)),
        detail: e.to_string(),
    }
}

/// The name a produced file takes: the source's own name with a suffix after it.
///
/// One rule in one place. The window shows what a run will write before it writes anything, and a
/// second copy of the rule would drift the moment either side was edited — so the planning command
/// and the signing path both come here.
fn beside(source: &str, suffix: &str) -> String {
    format!("{source}.{suffix}")
}

/// The open card session, and any signatures waiting on a decision.
#[derive(Default)]
pub struct AppState {
    session: Arc<Mutex<Option<CardSession>>>,
    /// Signatures that were made but not written, each with what stopped it.
    ///
    /// Held in memory only. A signature here is one the card has already produced, so it must not
    /// be lost to an unreachable authority or a full disk — but it must not survive the process
    /// either, since writing it later without the user asking would be writing a file they did not
    /// approve.
    pending: Mutex<Vec<Blocked>>,
    next: std::sync::atomic::AtomicU64,
    /// The 署名用証明書's details, once the password has been presented.
    ///
    /// Kept so the placement view can draw the panel the signature will actually carry, rather
    /// than a guess. Cleared with the session.
    signer: Mutex<Option<CertificateInfo>>,
    /// Set by [`cancel_timestamping`], cleared at the start of every run.
    ///
    /// Read only between items. A request already posted is left to finish: the authority has
    /// already seen the hash, so dropping the reply would cost the timestamp without buying any
    /// privacy back.
    cancelled: std::sync::atomic::AtomicBool,
}

impl AppState {
    fn next_id(&self) -> u64 {
        self.next.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    }

    /// Clear the cancel flag, so that a button pressed during the last run cannot stop this one.
    fn begin_run(&self) {
        self.cancelled
            .store(false, std::sync::atomic::Ordering::SeqCst);
    }

    fn is_cancelled(&self) -> bool {
        self.cancelled.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Drop a session whose card has gone.
    ///
    /// Not [`disconnect`]: there is nothing to power down, because the card that would have been
    /// cleared is no longer in the reader. Letting the session go is what makes the next call say
    /// `NotConnected` rather than fail again in the same obscure way.
    fn forget_session(&self) {
        drop(self.session.lock().expect("poisoned").take());
        *self.signer.lock().expect("poisoned") = None;
    }

    /// Run `body` with the open session, and find out whether the card is still there when it fails.
    ///
    /// The card is asked only after something has already gone wrong. Polling it would mean an
    /// unasked-for card operation on a timer for the sake of a label that is stale as soon as it is
    /// drawn; a failure is the one moment the question has an answer worth having.
    fn with_session<T>(&self, body: impl FnOnce(&mut CardSession) -> Result<T>) -> Result<T> {
        let mut guard = self
            .session
            .lock()
            .expect("the card session lock is poisoned");
        let session = guard.as_mut().ok_or(AppError::NotConnected)?;
        match body(session) {
            Err(error @ AppError::Card { .. }) => {
                if still_answering(session) {
                    return Err(error);
                }
                // The session goes, and the lock with it, before the certificate is cleared: two
                // locks held at once is a rule to break for a reason, and there is none here.
                drop(guard.take());
                drop(guard);
                *self.signer.lock().expect("poisoned") = None;
                Err(AppError::CardRemoved)
            }
            other => other,
        }
    }
}

/// Whether the card is still there, asked of a session that has just failed.
///
/// `status` is the cheapest thing a card can be asked that proves it is answering: no password, and
/// no retry counter spent.
fn still_answering(session: &mut CardSession) -> bool {
    session.status().is_ok()
}

// --- The card ---------------------------------------------------------------------------------

/// The PC/SC readers currently available.
#[tauri::command]
async fn list_readers() -> Result<Vec<String>> {
    Ok(myna_sign_card::list_readers()?)
}

/// Connect to a card and read what it says without a password.
#[tauri::command]
async fn connect(state: tauri::State<'_, AppState>, reader: Option<String>) -> Result<CardStatus> {
    let mut session = CardSession::connect(reader.as_deref())?;
    let status = session.status()?;
    *state.session.lock().expect("poisoned") = Some(session);
    Ok(status)
}

/// Power the card down and drop the session.
///
/// This is what clears the security status. Not optional, and not something to leave to process
/// exit — see the module documentation.
#[tauri::command]
async fn disconnect(state: tauri::State<'_, AppState>) -> Result<()> {
    *state.signer.lock().expect("poisoned") = None;
    let session = state.session.lock().expect("poisoned").take();
    match session {
        Some(session) => Ok(session.close()?),
        None => Ok(()),
    }
}

/// The 利用者証明用証明書, which needs no password and carries no 基本4情報.
#[tauri::command]
async fn auth_certificate(state: tauri::State<'_, AppState>) -> Result<CertificateInfo> {
    state.with_session(|session| Ok(session.auth_certificate()?))
}

/// Attempts left on the signature password, without spending one.
#[tauri::command]
async fn sign_pin_retries(state: tauri::State<'_, AppState>) -> Result<Option<u8>> {
    state.with_session(|session| Ok(session.sign_pin_retries()?.count()))
}

/// Present the signature password.
///
/// **The certificate this returns carries the holder's 氏名, 住所, 生年月日 and 性別.** The
/// interface shows them before anything is written to a file that would disclose them.
#[tauri::command]
async fn unlock(
    state: tauri::State<'_, AppState>,
    mut password: String,
) -> Result<CertificateInfo> {
    let result = state.with_session(|session| Ok(session.unlock(&mut password)?));
    // `CardSession::unlock` zeroes it too; this covers the paths that never reach it.
    use zeroize::Zeroize as _;
    password.zeroize();
    if let Ok(info) = &result {
        *state.signer.lock().expect("poisoned") = Some(info.clone());
    }
    result
}

// --- Signing ----------------------------------------------------------------------------------

/// What the interface asks for when signing files.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PgpRequest {
    /// The files.
    pub paths: Vec<String>,
    /// Embed the signer's certificate, so the `.asc` verifies on its own — and discloses the
    /// 基本4情報 to whoever receives it.
    pub embed_certificate: bool,
    /// Also write the OpenPGP public key, for verifying with `gpg`.
    pub export_public_key: bool,
    /// Produce a cleartext signed message rather than a detached signature.
    ///
    /// Text only, and the text is canonicalised — trailing whitespace cannot be signed.
    pub cleartext: bool,
    /// Also write the RFC 3161 token on its own, as `<file>.tsr`.
    pub write_tsr: bool,
    /// Where to get a timestamp.
    pub tsa: TsaConfig,
}

/// One signed file, written to disk.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SignResult {
    /// The file that was signed.
    pub source: String,
    /// What was written.
    pub output: String,
    /// SHA-256 of the input, so the interface can show what was signed.
    pub document_digest: String,
    /// The timestamp, when one was obtained.
    pub timestamp: Option<TimestampVerification>,
}

/// A signature that exists but has not reached the disk.
///
/// The card has already been used. Losing this because a timestamp authority was unreachable would
/// throw away a password entry and a card operation for a reason that has nothing to do with the
/// signature, so it is kept until the user says what to do with it.
enum Unwritten {
    // Boxed: an armored signature with a certificate in it dwarfs the PDF variant, and every
    // `Result` carrying one would otherwise be sized for the larger.
    Pgp(Box<openpgp::DetachedSignature>),
    Pdf(Box<pdf::sign::SignedPdf>),
}

impl Unwritten {
    /// What an RFC 3161 token is computed over.
    fn signature_value(&self) -> std::result::Result<Vec<u8>, Error> {
        match self {
            Unwritten::Pgp(signature) => signature.signature_value(),
            Unwritten::Pdf(signed) => Ok(signed.signature_value.clone()),
        }
    }

    fn attach_timestamp(&mut self, token: &[u8]) -> std::result::Result<(), Error> {
        match self {
            Unwritten::Pgp(signature) => signature.attach_timestamp(token),
            Unwritten::Pdf(signed) => signed.attach_timestamp(token),
        }
    }

    fn bytes(&self) -> &[u8] {
        match self {
            Unwritten::Pgp(signature) => &signature.armored,
            Unwritten::Pdf(signed) => &signed.bytes,
        }
    }
}

/// One signature waiting on a decision.
struct Pending {
    id: u64,
    unwritten: Unwritten,
    source: String,
    output: String,
    document_digest: String,
    tsa: TsaConfig,
    /// Write the RFC 3161 token beside the signature as well.
    write_tsr: bool,
    /// The timestamp, once one has been obtained and attached.
    ///
    /// Remembered because the token is attached the moment it verifies, which can be well before
    /// the file reaches the disk: a write that failed and is retried must still be able to say what
    /// the signature it is writing carries.
    timestamp: Option<TimestampVerification>,
}

/// Why a signature has not reached the disk.
///
/// Held per item, because a batch can have both: one authority that would not answer and one
/// directory that would not take a file are different problems with different answers, and a run
/// that funnelled them into one string could only ever report whichever happened first.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum Blocker {
    /// The authority did not answer, or its token did not verify.
    Timestamp {
        /// What happened, as the interface will show it.
        message: String,
    },
    /// The signature is complete; the destination is the problem.
    Write {
        /// What happened, as the interface will show it.
        message: String,
    },
}

impl Blocker {
    /// The authority did not answer, or would not.
    fn not_fetched(e: impl std::fmt::Display) -> Self {
        Blocker::Timestamp {
            message: format!("タイムスタンプを取得できませんでした。（{e}）"),
        }
    }

    /// A token came back and would not go into the signature.
    fn not_attached(e: impl std::fmt::Display) -> Self {
        Blocker::Timestamp {
            message: format!("タイムスタンプを署名に取り込めませんでした。（{e}）"),
        }
    }

    /// A token came back and did not stand up to checking, which is worse than none at all.
    fn not_verified(e: impl std::fmt::Display) -> Self {
        Blocker::Timestamp {
            message: format!("タイムスタンプを検証できませんでした。（{e}）"),
        }
    }

    /// The signature is finished and the destination refused it.
    fn not_written(e: impl std::fmt::Display) -> Self {
        Blocker::Write {
            message: format!("書き込みに失敗しました。（{e}）"),
        }
    }
}

/// A signature in the holding list, and why it is there.
struct Blocked {
    item: Pending,
    blocker: Blocker,
}

/// The file the card refused, and why.
///
/// Not a [`Blocker`]: nothing was produced for it, so there is nothing being held and nothing to
/// decide about.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SigningFailure {
    /// The file the card would not sign.
    pub path: String,
    /// What happened, as the interface will show it.
    pub message: String,
    /// Files after this one in the batch that were never sent to the card.
    pub skipped: Vec<String>,
}

/// What the interface shows about a signature that is waiting.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PendingInfo {
    /// Identifies it in [`resolve_pending`].
    pub id: u64,
    /// The file that was signed.
    pub source: String,
    /// Where it would be written.
    pub output: String,
    /// SHA-256 of the input.
    pub document_digest: String,
    /// What is standing between this signature and the disk.
    pub blocked_by: Blocker,
}

impl Blocked {
    fn info(&self) -> PendingInfo {
        PendingInfo {
            id: self.item.id,
            source: self.item.source.clone(),
            output: self.item.output.clone(),
            document_digest: self.item.document_digest.clone(),
            blocked_by: self.blocker.clone(),
        }
    }
}

/// A file written beside the signature.
///
/// Only ever describes what actually happened. A convenience that failed to write is still worth
/// reporting — but as a file that is not there, never as an output.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SideOutput {
    /// Where it was to go.
    pub path: String,
    /// What it is.
    pub kind: SideOutputKind,
    /// Whether it reached the disk.
    pub written: bool,
    /// Why it did not. `None` when it did.
    pub error: Option<String>,
}

/// The kinds of file a signing run writes that are not the signature itself.
#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum SideOutputKind {
    /// The OpenPGP public key, for verifying with `gpg`.
    PublicKey,
    /// The RFC 3161 token on its own, for `openssl ts -verify`.
    TimestampToken,
}

/// What a signing run produced.
///
/// A run can do all of these at once: some files written, others waiting on a timestamp, and one
/// the card refused. Reporting them separately is what lets one unreachable authority stop being a
/// reason to lose the batch.
#[derive(Debug, Clone, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct SignOutcome {
    /// Signatures that reached the disk.
    pub written: Vec<SignResult>,
    /// Signatures held back, each with what is holding it.
    pub pending: Vec<PendingInfo>,
    /// The file the card refused, when one did.
    pub signing_error: Option<SigningFailure>,
    /// Public keys and `.tsr` tokens, as they actually turned out.
    pub side_outputs: Vec<SideOutput>,
    /// How many files the run was asked to sign, so the interface can show a total that adds up.
    pub requested: usize,
}

/// What to do with a signature that did not reach the disk.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum PendingAction {
    /// Ask the authority again. No card operation and no password: the signature already exists.
    Retry,
    /// Write it as it is. The signature is valid; it just cannot outlive the certificate.
    WriteWithoutTimestamp,
    /// Throw it away.
    Discard,
    /// Write it somewhere else.
    WriteTo {
        /// One destination per id, in the same order. They come from a save dialog, never from the
        /// page: this command writes wherever it is told, so the choice has to be the user's.
        outputs: Vec<String>,
    },
}

/// Why the card would not sign one file, as a sentence the window can show unchanged.
///
/// The window has its own wording for [`AppError`], but a refusal partway through a batch never
/// reaches it as one: it arrives inside a result that also carries signatures. So the sentence is
/// built here, where the failure is known.
fn signing_message(error: &AppError) -> String {
    match error {
        AppError::CardRemoved => "カードが応答しなくなりました。".into(),
        AppError::PinBlocked => "署名用パスワードがロックされました。".into(),
        AppError::PinIncorrect { .. } => "署名用パスワードが違います。".into(),
        AppError::NotConnected => "カードが接続されていません。".into(),
        AppError::Card { message } => format!("カードが署名を拒否しました。（{message}）"),
        AppError::Io { operation, detail } => format!("{operation}に失敗しました。（{detail}）"),
        AppError::NotText { path } => {
            format!("{} はテキストではありません。", file_label(path))
        }
        AppError::Failed { message } => message.clone(),
    }
}

/// Where a signing run has got to, for the progress display.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct Progress<'a> {
    index: usize,
    total: usize,
    path: &'a str,
    stage: &'a str,
}

fn report(app: &tauri::AppHandle, index: usize, total: usize, path: &str, stage: &str) {
    use tauri::Emitter as _;
    // A batch signs on one password entry and can take a while — a card operation per file, and a
    // network round trip per file when timestamping. Saying which file is being worked on is the
    // difference between "working" and "hung".
    let _ = app.emit(
        "sign-progress",
        Progress {
            index,
            total,
            path,
            stage,
        },
    );
}

/// Try to timestamp, then write.
///
/// On a failure the signature comes back untouched, along with what is standing in its way. It is
/// never written half-done and never dropped.
#[allow(
    clippy::result_large_err,
    reason = "the point of the Err variant is that it carries the signature back rather than \
              dropping it; boxing would only move the same bytes behind a pointer"
)]
fn timestamp_and_write(
    mut item: Pending,
    side_outputs: &mut Vec<SideOutput>,
) -> std::result::Result<SignResult, (Pending, Blocker)> {
    if let Some(url) = item.tsa.url() {
        let signature_value = match item.unwritten.signature_value() {
            Ok(value) => value,
            Err(e) => return Err((item, Blocker::not_fetched(e))),
        };
        match tsa::fetch(&BlockingHttp::default(), url, &signature_value) {
            Ok(token) => {
                if let Err(e) = item.unwritten.attach_timestamp(&token) {
                    return Err((item, Blocker::not_attached(e)));
                }
                let anchors = match item.tsa.anchors() {
                    Ok(anchors) => anchors,
                    Err(e) => return Err((item, Blocker::not_verified(e))),
                };
                match tsa::verify_token_with(&token, &signature_value, &anchors) {
                    Ok(verified) => item.timestamp = Some(verified),
                    Err(e) => return Err((item, Blocker::not_verified(e))),
                }
                // The token is in the signature now. If the write below fails, the retry must not
                // ask the authority a second time: a second token would be attached beside the
                // first, and an OpenPGP signature would carry the notation twice.
                item.tsa = TsaConfig::None;
            }
            Err(e) => return Err((item, Blocker::not_fetched(e))),
        }
    }

    // The token on its own, for checking with `openssl ts -verify`. Best effort: it is a
    // convenience beside a signature that is already complete, so failing to write it must not hold
    // the signature back — but it is reported either way, because a file that was not written is
    // not an output.
    if item.write_tsr
        && let Unwritten::Pgp(signature) = &item.unwritten
        && let Some(token) = openpgp::embedded_timestamp(&signature.signature)
    {
        let path = beside(&item.source, "tsr");
        let failure = std::fs::write(&path, token).err();
        side_outputs.push(SideOutput {
            path,
            kind: SideOutputKind::TimestampToken,
            written: failure.is_none(),
            error: failure.map(|e| format!("書き込みに失敗しました。（{e}）")),
        });
    }

    match std::fs::write(&item.output, item.unwritten.bytes()) {
        Ok(()) => Ok(SignResult {
            source: item.source,
            output: item.output,
            document_digest: item.document_digest,
            timestamp: item.timestamp,
        }),
        // A failed write is not a timestamp problem, but the signature is just as worth keeping —
        // the user can free some space and retry.
        Err(e) => Err((item, Blocker::not_written(e))),
    }
}

/// Run each freshly made signature through timestamping and writing, holding back the failures.
///
/// The progress event goes out immediately before each item is worked on rather than for the whole
/// batch up front: a run that announced "10/10" and then sat on a fifteen second timeout per file
/// would be telling the user it had finished while it had not started.
fn settle(
    app: &tauri::AppHandle,
    state: &AppState,
    items: Vec<Pending>,
    total: usize,
    outcome: &mut SignOutcome,
) {
    for (index, item) in items.into_iter().enumerate() {
        let timestamping = item.tsa.url().is_some();
        // Cancelling is about the wait on the network, so an item with nothing to fetch is written
        // anyway: holding it back would deny a signature for a reason the user did not give. And
        // what is held back was stopped, not failed — the wording has to say so.
        if timestamping && state.is_cancelled() {
            hold(
                state,
                outcome,
                item,
                Blocker::Timestamp {
                    message: "取得を中止しました。".into(),
                },
            );
            continue;
        }
        // "タイムスタンプ取得中" would be a lie for an item with no authority to ask.
        let stage = if timestamping {
            "timestamping"
        } else {
            "writing"
        };
        report(app, index, total, &item.source, stage);
        match timestamp_and_write(item, &mut outcome.side_outputs) {
            Ok(result) => outcome.written.push(result),
            Err((item, blocker)) => hold(state, outcome, item, blocker),
        }
    }
    report(app, total, total, "", "done");
}

/// Keep a signature that did not reach the disk, and say why once.
fn hold(state: &AppState, outcome: &mut SignOutcome, item: Pending, blocker: Blocker) {
    let held = Blocked { item, blocker };
    outcome.pending.push(held.info());
    state.pending.lock().expect("poisoned").push(held);
}

/// The kinds of file a signing run writes.
#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum PlannedKind {
    /// The signature itself.
    Signature,
    /// The OpenPGP public key.
    PublicKey,
    /// The RFC 3161 token on its own.
    TimestampToken,
}

/// One file a signing run would write.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PlannedOutput {
    /// The file this comes from, when it comes from one.
    pub source: Option<String>,
    /// Where it would go.
    pub path: String,
    /// What it would be.
    pub kind: PlannedKind,
    /// Something is already there and would be replaced.
    pub exists: bool,
}

/// What [`sign_files`] would write.
///
/// Asked rather than worked out again in the window: the naming rule lives here and in the command
/// line tool already, and a third copy would drift until the list on screen stopped being the list
/// on disk. Touches no card and writes nothing.
#[tauri::command]
async fn plan_outputs(request: PgpRequest) -> Result<Vec<PlannedOutput>> {
    let planned = |source: Option<&String>, path: String, kind: PlannedKind| PlannedOutput {
        source: source.cloned(),
        exists: std::path::Path::new(&path).exists(),
        path,
        kind,
    };

    let mut outputs = Vec::new();
    for path in &request.paths {
        outputs.push(planned(
            Some(path),
            beside(path, "asc"),
            PlannedKind::Signature,
        ));
        // Only when there will be a token to write. Listing a `.tsr` that no authority is going to
        // supply would promise a file that never appears.
        if request.write_tsr && request.tsa.url().is_some() {
            outputs.push(planned(
                Some(path),
                beside(path, "tsr"),
                PlannedKind::TimestampToken,
            ));
        }
    }
    // One key, beside the first file, because that is what signing does. Listing it once per file
    // would describe files the run will not write.
    if request.export_public_key
        && let Some(first) = request.paths.first()
    {
        outputs.push(planned(
            Some(first),
            beside(first, "pubkey.asc"),
            PlannedKind::PublicKey,
        ));
    }
    Ok(outputs)
}

/// What the card managed before it stopped, when it stopped.
///
/// A refusal partway through a batch cannot be unwound past: the signatures already made cost a
/// card operation each and are worth exactly as much as the one that failed is not.
struct Made {
    items: Vec<Pending>,
    /// The file the card refused, when it refused one.
    failure: Option<SigningFailure>,
    side_outputs: Vec<SideOutput>,
    /// The card stopped answering, so the session has to go.
    removed: bool,
}

/// Sign files, writing detached OpenPGP signatures beside them.
#[tauri::command]
async fn sign_files(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    request: PgpRequest,
) -> Result<SignOutcome> {
    state.begin_run();
    let total = request.paths.len();

    // Everything that can fail without costing a card operation happens first. Reading a file the
    // user cannot read, or a directory that cannot be written to, must not be discovered halfway
    // through a batch — by then there would be signatures in hand, and an early return would throw
    // them away.
    let mut documents = Vec::with_capacity(total);
    for path in &request.paths {
        let bytes = std::fs::read(path).map_err(|e| read_error(path, e))?;
        // A cleartext signature is over text, and the whole batch is checked here rather than as
        // each file comes up: finding the fifth file is a JPEG after four card operations would
        // mean discovering it with signatures in hand.
        if request.cleartext && std::str::from_utf8(&bytes).is_err() {
            return Err(AppError::NotText { path: path.clone() });
        }
        documents.push((path.clone(), bytes));
    }

    let made = state.with_session(|session| {
        let mut signer = session.signer()?;
        let mut side_outputs = Vec::new();

        // The public key too: it takes its own card signature, and doing it before the documents
        // means a failure here costs nothing that has to be kept.
        if request.export_public_key
            && let Some(first) = request.paths.first()
        {
            let name = CertificateInfo::read(signer.certificate())?
                .common_name
                .unwrap_or_else(|| "My Number Card".into());
            let armored = openpgp::export_certificate(&mut signer, &name)?;
            let output = beside(first, "pubkey.asc");
            // Still fatal, and still safe to be: nothing has been signed yet, and a directory that
            // will not take this file will not take the signatures either.
            std::fs::write(&output, &armored).map_err(|e| write_error(&output, e))?;
            side_outputs.push(SideOutput {
                path: output,
                kind: SideOutputKind::PublicKey,
                written: true,
                error: None,
            });
        }

        let options = SignOptions {
            embed_certificate: request.embed_certificate,
            created: Some(Timestamp::now()?),
        };

        let mut items = Vec::new();
        for (index, (path, bytes)) in documents.iter().enumerate() {
            report(&app, index, total, path, "signing");
            // A card refusal partway through still loses the signatures already made. Rather than
            // let `?` do that, each one is kept and the failure is reported once the batch ends.
            let made = if request.cleartext {
                // The batch was checked for text before the card was touched, so the only way this
                // fails now is a file that changed underneath the run.
                match std::str::from_utf8(bytes) {
                    Ok(text) => openpgp::sign_cleartext(&mut signer, text, &options),
                    Err(_) => Err(Error::malformed(format!(
                        "{path} is not text, so it cannot be signed as a cleartext message"
                    ))),
                }
            } else {
                openpgp::sign_detached(&mut signer, &bytes[..], &options)
            };

            match made {
                Ok(signature) => items.push(Pending {
                    id: state.next_id(),
                    unwritten: Unwritten::Pgp(Box::new(signature)),
                    source: path.clone(),
                    output: beside(path, "asc"),
                    document_digest: hex::encode(myna_sign_core::signer::sha256(bytes)),
                    tsa: request.tsa.clone(),
                    write_tsr: request.write_tsr,
                    timestamp: None,
                }),
                // Nothing has been produced yet, so the typed error is worth more than a report of
                // it: a blocked password and a card that has gone each need their own screen, and
                // `SigningFailure` carries prose and nothing else.
                Err(e) if items.is_empty() => return Err(e.into()),
                Err(e) => {
                    // Something was already signed; hand it back rather than unwind past it. The
                    // signer is let go first so the card can be asked the question `with_session`
                    // would have asked: "refused" and "gone" are different situations.
                    drop(signer);
                    let error = AppError::from(e);
                    let removed =
                        matches!(error, AppError::Card { .. }) && !still_answering(session);
                    let error = if removed { AppError::CardRemoved } else { error };
                    return Ok(Made {
                        items,
                        failure: Some(SigningFailure {
                            path: path.clone(),
                            message: signing_message(&error),
                            skipped: documents[index + 1..]
                                .iter()
                                .map(|(path, _)| path.clone())
                                .collect(),
                        }),
                        side_outputs,
                        removed,
                    });
                }
            }
        }
        Ok(Made {
            items,
            failure: None,
            side_outputs,
            removed: false,
        })
    })?;

    // The session could not be dropped while the batch held the card, so it is dropped now.
    if made.removed {
        state.forget_session();
    }

    // The card is done with; everything from here is files and the network, and none of it can
    // cost another password entry.
    let mut outcome = SignOutcome {
        signing_error: made.failure,
        side_outputs: made.side_outputs,
        requested: total,
        ..Default::default()
    };
    settle(&app, &state, made.items, total, &mut outcome);
    Ok(outcome)
}

/// What the interface asks for when signing a PDF.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PdfRequest {
    /// The PDF.
    pub path: String,
    /// Where to write the result.
    pub output: String,
    /// `/Reason`.
    pub reason: Option<String>,
    /// `/Location`.
    pub location: Option<String>,
    /// Put nothing on the page at all.
    ///
    /// Otherwise something is always drawn: the image the signer chose, or a panel describing the
    /// signature.
    pub invisible: bool,
    /// Where the signer put it. Left out, a sensible corner is chosen.
    pub appearance: Option<AppearanceRequest>,
    /// Where to get a timestamp.
    pub tsa: TsaConfig,
}

/// Where a visible signature goes.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AppearanceRequest {
    /// Page, counting from 1.
    pub page: usize,
    /// `[x1 y1 x2 y2]` in PDF user space, origin at the bottom left.
    pub rect: [f32; 4],
    /// Path to an image of the signer's own, or nothing for the drawn panel.
    pub image_path: Option<String>,
}

/// Draw the panel the signature will carry.
///
/// Uses the 署名用証明書 once the password has been presented. Before that the holder's name is
/// not readable — it is behind the password — so the preview says so rather than inventing one.
fn signature_panel(
    state: &AppState,
    reason: Option<&str>,
    location: Option<&str>,
) -> Result<pdf::SignatureImage> {
    let known = state.signer.lock().expect("poisoned").clone();
    let block = match known {
        Some(certificate) => {
            pdf::SignatureBlock::describe(&certificate, Timestamp::now()?, reason, location)
        }
        None => {
            let mut rows = vec![
                (
                    "署名者".to_string(),
                    "（カードから取得されます）".to_string(),
                ),
                (
                    "日時".to_string(),
                    Timestamp::now()?.to_rfc3339()[..16].replace('T', " ") + " UTC",
                ),
            ];
            for (label, value) in [("理由", reason), ("場所", location)] {
                if let Some(value) = value.filter(|v| !v.trim().is_empty()) {
                    rows.push((label.to_string(), value.to_string()));
                }
            }
            pdf::SignatureBlock {
                title: "電子署名".into(),
                rows,
            }
        }
    };
    Ok(block.render()?)
}

/// What would be drawn on the page: the signer's image, or the panel.
fn drawn_image(
    state: &AppState,
    image_path: Option<&str>,
    reason: Option<&str>,
    location: Option<&str>,
) -> Result<pdf::SignatureImage> {
    match image_path {
        Some(path) => Ok(pdf::SignatureImage::from_bytes(
            std::fs::read(path).map_err(|e| read_error(path, e))?,
        )),
        None => signature_panel(state, reason, location),
    }
}

/// Where the signature would go if the signer places it nowhere.
///
/// The placement view shows this so the default is visible rather than a surprise. It is the same
/// rule the signing path applies, asked rather than reimplemented — two copies would drift, and
/// the one on screen would stop being the one in the file.
#[tauri::command]
async fn default_signature_placement(
    state: tauri::State<'_, AppState>,
    path: String,
    image_path: Option<String>,
    reason: Option<String>,
    location: Option<String>,
) -> Result<AppearanceRequest> {
    let pdf_bytes = std::fs::read(&path).map_err(|e| read_error(&path, e))?;
    let image = drawn_image(
        &state,
        image_path.as_deref(),
        reason.as_deref(),
        location.as_deref(),
    )?;
    let appearance = pdf::default_placement(&pdf_bytes, 1, &image)?;
    Ok(AppearanceRequest {
        page: appearance.page,
        rect: appearance.rect,
        image_path,
    })
}

/// The panel, as bytes the placement view can show.
#[tauri::command]
async fn preview_signature_panel(
    state: tauri::State<'_, AppState>,
    reason: Option<String>,
    location: Option<String>,
) -> Result<tauri::ipc::Response> {
    let image = signature_panel(&state, reason.as_deref(), location.as_deref())?;
    Ok(tauri::ipc::Response::new(image.bytes))
}

/// Sign a PDF.
#[tauri::command]
async fn sign_pdf(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    request: PdfRequest,
) -> Result<SignOutcome> {
    state.begin_run();
    // Read before signing, so a missing file or an unreadable image is found while nothing has
    // been produced yet.
    let original = std::fs::read(&request.path).map_err(|e| read_error(&request.path, e))?;
    // What is drawn, and where. An invisible signature skips both.
    let appearance = if request.invisible {
        None
    } else {
        let drawn = match request
            .appearance
            .as_ref()
            .and_then(|a| a.image_path.as_ref())
        {
            Some(path) => {
                pdf::SignatureImage::from_bytes(std::fs::read(path).map_err(|e| read_error(path, e))?)
            }
            None => signature_panel(
                &state,
                request.reason.as_deref(),
                request.location.as_deref(),
            )?,
        };
        Some(match &request.appearance {
            Some(a) => pdf::Appearance {
                page: a.page,
                rect: a.rect,
                image: Some(drawn),
            },
            None => pdf::default_placement(&original, 1, &drawn)?,
        })
    };

    let item = state.with_session(|session| {
        let extra_certificates = session.sign_ca_certificate_der().into_iter().collect();

        let options = pdf::PdfSignOptions {
            reason: request.reason.clone(),
            location: request.location.clone(),
            appearance,
            extra_certificates,
            ..Default::default()
        };

        report(&app, 0, 1, &request.path, "signing");
        let mut signer = session.signer()?;
        let signed = pdf::sign(&mut signer, &original, &options)?;

        Ok(Pending {
            id: state.next_id(),
            unwritten: Unwritten::Pdf(Box::new(signed)),
            source: request.path.clone(),
            output: request.output.clone(),
            document_digest: hex::encode(myna_sign_core::signer::sha256(&original)),
            tsa: request.tsa.clone(),
            write_tsr: false,
            timestamp: None,
        })
    })?;

    let mut outcome = SignOutcome {
        requested: 1,
        ..Default::default()
    };
    settle(&app, &state, vec![item], 1, &mut outcome);
    Ok(outcome)
}

/// Decide what happens to signatures that did not reach the disk.
///
/// Takes no card and no password — the signatures already exist. It reports progress the same way a
/// signing run does, because it does the same work: retrying ten of them is ten more waits on the
/// same authority, and silence for that long is indistinguishable from a hang.
#[tauri::command]
async fn resolve_pending(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    ids: Vec<u64>,
    action: PendingAction,
) -> Result<SignOutcome> {
    state.begin_run();

    // Checked before anything leaves the holding list. Returning an error with the signatures
    // already in hand is the one way this command could lose them.
    if let PendingAction::WriteTo { outputs } = &action
        && outputs.len() != ids.len()
    {
        return Err(AppError::Failed {
            message: "書き出し先の数が、選ばれた署名の数と合いません。".into(),
        });
    }

    let mut taken: Vec<Pending> = {
        let mut held = state.pending.lock().expect("poisoned");
        let (taken, kept): (Vec<Blocked>, Vec<Blocked>) =
            held.drain(..).partition(|held| ids.contains(&held.item.id));
        *held = kept;
        taken.into_iter().map(|held| held.item).collect()
    };
    let requested = taken.len();

    match action {
        // Dropping them is the whole action: the signature goes and nothing is written.
        PendingAction::Discard => taken.clear(),
        PendingAction::WriteWithoutTimestamp => {
            for item in &mut taken {
                item.tsa = TsaConfig::None;
            }
        }
        PendingAction::Retry => {}
        PendingAction::WriteTo { outputs } => {
            // Paired by id rather than by position: the holding list is in the order things were
            // signed, and `ids` is in the order the window offered them.
            for (id, output) in ids.iter().zip(outputs) {
                if let Some(item) = taken.iter_mut().find(|item| item.id == *id) {
                    item.output = output;
                }
            }
        }
    }

    let mut outcome = SignOutcome {
        requested,
        ..Default::default()
    };
    let total = taken.len();
    settle(&app, &state, taken, total, &mut outcome);
    Ok(outcome)
}

/// Signatures still waiting on a decision.
///
/// The interface asks on start-up, so that a window closed mid-decision does not hide them.
#[tauri::command]
async fn list_pending(state: tauri::State<'_, AppState>) -> Result<Vec<PendingInfo>> {
    Ok(state
        .pending
        .lock()
        .expect("poisoned")
        .iter()
        .map(Blocked::info)
        .collect())
}

/// Stop asking the timestamp authority.
///
/// Takes effect between items. A request already posted is left to finish: the authority has
/// already seen the hash, so dropping the reply would lose the timestamp without taking anything
/// back. Whatever has not been started is held as pending — which is not a failure, and must not be
/// reported as one. The signature exists and can still be written.
#[tauri::command]
async fn cancel_timestamping(state: tauri::State<'_, AppState>) -> Result<()> {
    state
        .cancelled
        .store(true, std::sync::atomic::Ordering::SeqCst);
    Ok(())
}

// --- Verifying (no card needed) -----------------------------------------------------------------

/// Check a timestamp authority is reachable and its tokens verify.
#[tauri::command]
async fn test_tsa(config: TsaConfig) -> Result<TimestampVerification> {
    let url = config.url().ok_or_else(|| AppError::Failed {
        message: "no authority is configured".into(),
    })?;
    let probe = b"myna-sign connection test";
    let token = tsa::fetch(&BlockingHttp::default(), url, probe)?;
    Ok(tsa::verify_token_with(&token, probe, &config.anchors()?)?)
}

/// Verify a detached OpenPGP signature.
#[tauri::command]
async fn verify_detached(
    signature_path: String,
    document_path: String,
    accept_test_hierarchy: bool,
) -> Result<openpgp::PgpVerification> {
    let armored = std::fs::read(&signature_path).map_err(|e| read_error(&signature_path, e))?;
    let document =
        std::fs::File::open(&document_path).map_err(|e| read_error(&document_path, e))?;
    Ok(openpgp::verify_detached(
        &armored,
        document,
        &openpgp::VerifyOptions {
            certificate: None,
            accept_test_hierarchy,
        },
    )?)
}

/// Verify the signatures in a PDF.
#[tauri::command]
async fn verify_pdf(
    path: String,
    accept_test_hierarchy: bool,
) -> Result<Vec<pdf::PdfSignatureVerification>> {
    let bytes = std::fs::read(&path).map_err(|e| read_error(&path, e))?;
    Ok(pdf::verify(
        &bytes,
        &pdf::verify::VerifyOptions {
            accept_test_hierarchy,
            timestamp_anchors: None,
        },
    )?)
}

/// Write a verification result out as plain text.
///
/// The claims themselves come from the window, which is where their wording already lives; the
/// header and the two closing sentences are added here so that no caller can leave them out. They
/// are the difference between a note someone made and a document that looks like a finding.
///
/// Plain text only, and deliberately so. Anything with a letterhead in it would be a file that
/// carries more authority than this program has: nothing here is signed, and nothing here has
/// consulted a revocation service.
#[tauri::command]
async fn export_verification(path: String, lines: Vec<String>) -> Result<()> {
    let is_text = std::path::Path::new(&path)
        .extension()
        .is_some_and(|extension| extension.eq_ignore_ascii_case("txt"));
    if !is_text {
        return Err(AppError::Failed {
            message: "検証結果はテキストファイル（.txt）としてのみ書き出せます。".into(),
        });
    }

    let mut text = String::from("myna-sign 検証結果\n");
    text.push_str(&format!("生成: {}\n\n", Timestamp::now()?.to_jst_minutes()));
    for line in &lines {
        text.push_str(line);
        text.push('\n');
    }
    text.push_str("\nこのファイルは署名されていません。内容は誰でも書き換えられます。\n");
    text.push_str(
        "本アプリは失効情報サービスを参照しません。証明書が失効していても、この結果は変わりません。\n",
    );

    std::fs::write(&path, text).map_err(|e| write_error(&path, e))
}

/// The largest file the placement view will load into the window.
///
/// A signature can be put on a PDF of any size; only the *preview* is capped, and a document past
/// this is signed with coordinates typed in instead of drawn.
const PREVIEW_LIMIT: u64 = 64 * 1024 * 1024;

/// Read a file for the window to display.
///
/// Used by the signature placement view, which has to render the PDF and the stamp image. The
/// window cannot reach the filesystem itself — there is no blanket `fs` permission — so this is
/// the one way bytes get in, and it is deliberately read-only and capped.
///
/// It will read any path it is given. That is acceptable here and nowhere near as broad as it
/// sounds: the window runs only the code bundled with the application, its CSP forbids loading
/// anything remote, and `connect-src` gives it no way to send what it read anywhere. The
/// application's own network access — the timestamp authority — happens in Rust and carries a
/// 32 byte hash.
#[tauri::command]
async fn read_file(path: String) -> Result<tauri::ipc::Response> {
    let length = std::fs::metadata(&path)
        .map_err(|e| read_error(&path, e))?
        .len();
    if length > PREVIEW_LIMIT {
        return Err(AppError::Failed {
            message: format!(
                "{path} は {} MB あり、プレビューの上限 {} MB を超えています。座標を入力して配置してください。",
                length / 1024 / 1024,
                PREVIEW_LIMIT / 1024 / 1024
            ),
        });
    }
    let bytes = std::fs::read(&path).map_err(|e| read_error(&path, e))?;
    Ok(tauri::ipc::Response::new(bytes))
}

/// SHA-256 of a file, so the confirmation screen can show what is about to be signed.
#[tauri::command]
async fn document_digest(path: String) -> Result<String> {
    let bytes = std::fs::read(&path).map_err(|e| read_error(&path, e))?;
    Ok(hex::encode(myna_sign_core::signer::sha256(&bytes)))
}

/// Start the application.
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(AppState::default())
        .invoke_handler(tauri::generate_handler![
            list_readers,
            connect,
            disconnect,
            auth_certificate,
            sign_pin_retries,
            unlock,
            plan_outputs,
            sign_files,
            sign_pdf,
            resolve_pending,
            list_pending,
            cancel_timestamping,
            test_tsa,
            verify_detached,
            verify_pdf,
            export_verification,
            document_digest,
            read_file,
            preview_signature_panel,
            default_signature_placement,
        ])
        .build(tauri::generate_context!())
        .expect("the application failed to start")
        .run(|app, event| {
            // The last chance to clear the card's security status. Without this, quitting with a
            // card still in the reader leaves the signature key unlocked.
            if let tauri::RunEvent::Exit = event
                && let Some(state) = app.try_state::<AppState>()
                && let Some(session) = state.session.lock().expect("poisoned").take()
            {
                let _ = session.close();
            }
        });
}
