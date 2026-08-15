/**
 * The Rust side, typed.
 *
 * Every call goes through `invoke`. Nothing in the window talks to the network, reads a file, or
 * touches the card directly — those all happen in Rust, which is what lets the capability list
 * stay as short as it is.
 *
 * The types below mirror `src-tauri/src/lib.rs` field for field. Where the two disagree, Rust is
 * right: it is the side holding the data, and a shape invented here would only be a guess about
 * what arrives.
 */
import { invoke } from "@tauri-apps/api/core";

export interface CardStatus {
  reader: string;
  tokenType: string;
  physicalCard: boolean;
  hasSignCertificate: boolean;
  hasAuthCertificate: boolean;
  signPinRetries: number | null;
  authPinRetries: number | null;
}

/**
 * Which characters of a name or address were replaced by a substitute.
 *
 * Where a position is listed, the text the certificate carries is not the text on the resident
 * register — the character could not be represented and stands in for another one.
 */
export interface Substitutes {
  /**
   * Character positions that are substitutes, counting from 1.
   *
   * Only meaningful while `lengthMatches` is true. When it is false the flags describe a different
   * number of characters than the field has, so a position here can point at the wrong character —
   * marking by it would put the warning on a character that is not a substitute, and leave the one
   * that is unmarked. Read them through `substitutePositions`, which refuses in that case.
   */
  positions: number[];
  raw: string;
  /** False when the flags do not describe as many characters as the field has. */
  lengthMatches: boolean;
}

/**
 * The positions worth marking, or nothing when the flags and the field disagree about the length.
 *
 * A caller that wants to underline characters has to go through this: `positions` on its own is
 * only as trustworthy as `lengthMatches`, and the mismatch is reported in words instead — see
 * `describeSubstitutes`.
 */
export function substitutePositions(
  substitutes: Substitutes | null,
): number[] | null {
  if (!substitutes || !substitutes.lengthMatches) return null;
  return substitutes.positions;
}

/** What the 署名用証明書 says about its holder. Every field discloses something. */
export interface Holder {
  name: string | null;
  birthDate: string | null;
  sex: string | null;
  address: string | null;
  nameSubstitutes: Substitutes | null;
  addressSubstitutes: Substitutes | null;
  other: [string, string][];
}

/**
 * An instant, in Japan Standard Time.
 *
 * Every time the Rust side hands over is UTC and machine-readable — that is what belongs in a
 * signed document and in an API. What belongs on screen is the reader's own clock, and for this
 * program that is Tokyo.
 */
export function formatJst(instant: string | null | undefined): string {
  if (!instant) return "—";
  const at = new Date(instant);
  if (Number.isNaN(at.getTime())) return instant;
  const parts = new Intl.DateTimeFormat("ja-JP", {
    timeZone: "Asia/Tokyo",
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  }).formatToParts(at);
  const get = (type: string) => parts.find((p) => p.type === type)?.value ?? "";
  return `${get("year")}-${get("month")}-${get("day")} ${get("hour")}:${get("minute")}:${get("second")} JST`;
}

/** 性別 is a JIS X 0303 code, not a word. */
export function describeSex(code: string | null): string | null {
  switch (code) {
    case "1":
      return "男性";
    case "2":
      return "女性";
    case "9":
      return "適用不能";
    default:
      return code;
  }
}

/** A sentence about substituted characters, or nothing when there are none. */
export function describeSubstitutes(
  label: string,
  substitutes: Substitutes | null,
): string | null {
  if (!substitutes) return null;
  if (!substitutes.lengthMatches) {
    return `${label}の代替文字情報が文字数と一致しません（${substitutes.raw}）。`;
  }
  if (substitutes.positions.length === 0) return null;
  return `${label}の ${substitutes.positions.join("、")} 文字目に代替文字が使われています。戸籍上の表記とは異なります。`;
}

// --- Vocabulary ---------------------------------------------------------------------------------

/**
 * Words for the things whose own names are jargon.
 *
 * PC/SC, X.509 and JPKI each have a term for these, and the term is what ends up on screen unless
 * a replacement is written down somewhere both the card screen and the certificate table can read
 * it. Kept here rather than in a component so the two cannot drift into calling one thing by two
 * names.
 */
export const LABELS = {
  /** PC/SC says "token". What is on the reader is a card or a phone, so say which was read. */
  token: "読み取った媒体",
  /** X.509 says "subject"; 主体者 translates the term without explaining it to anybody. */
  subject: "証明書の記載名（DN）",
} as const;

/**
 * A blocked signature password, in the three registers it has to be said in.
 *
 * One string cannot do all three jobs. A `Claim` value sits next to a label that already names the
 * password and has one line to fit in; a status line has room for the remedy; a sentence standing
 * on its own has to name what is blocked before it can say anything else. Using the full sentence
 * in a `Claim` is what breaks that layout, so the short forms exist here rather than being cut
 * down at each call site.
 */
export const PIN_BLOCKED = {
  /** Beside a label that already says which password this is. */
  claim: "ロック済み",
  /** A status line, where the remedy fits. */
  status: "ロック済み — 市区町村の窓口でのみ解除できます",
  /** Alone, in an error, where nothing else supplies the subject. */
  sentence: "署名用パスワードがロックされています。市区町村の窓口でのみ解除できます。",
} as const;

// --- Certificates and verification --------------------------------------------------------------

export interface CertificateInfo {
  subject: string;
  commonName: string | null;
  issuer: string;
  serialNumber: string;
  notBefore: string;
  notAfter: string;
  keyBits: number;
  fingerprint: string;
  holder: Holder;
}

export type ReferenceDate =
  | { source: "timestamp"; at: string }
  | { source: "now"; at: string };

export type TrustCheck =
  | {
      result: "chainVerified";
      testHierarchy: boolean;
      reference: ReferenceDate;
      /** Always false in this version. Shown as "not checked", never as "not revoked". */
      revocationChecked: boolean;
    }
  | { result: "failed"; reason: string };

export interface ChainOutcome {
  verified: boolean;
  anchor: string | null;
  reason: string | null;
  path: string[];
  withinValidity: boolean;
}

export interface TimestampVerification {
  verified: boolean;
  imprintMatches: boolean;
  signatureVerified: boolean;
  timestampingEku: boolean;
  chain: ChainOutcome;
  genTime: string;
  genTimeUnix: number;
  policy: string;
  tsaName: string | null;
  serialNumber: string;
  accuracySeconds: number | null;
}

export interface PgpVerification {
  signatureVerified: boolean;
  claimedCreationTime: string | null;
  certificate: CertificateInfo | null;
  keyMatchesCertificate: boolean;
  trust: TrustCheck | null;
  timestamp: TimestampVerification | null;
}

export interface PdfSignatureVerification {
  fieldName: string | null;
  claimedName: string | null;
  reason: string | null;
  location: string | null;
  claimedSigningTime: string | null;
  /**
   * The CMS signature over `signedAttrs` verifies under this certificate's key.
   *
   * This says nothing about the document: the bytes are reached through the `messageDigest`
   * attribute, which is `documentDigestMatches`. The two are separate on purpose — a genuine
   * signature over somebody else's document is exactly the pair `true` and `false`.
   */
  signatureVerified: boolean;
  documentDigestMatches: boolean;
  byteRangeSound: boolean;
  coversWholeFile: boolean;
  bytesAfter: number;
  certificate: CertificateInfo | null;
  trust: TrustCheck | null;
  timestamp: TimestampVerification | null;
  /**
   * `signingCertificateV2` is present and names this certificate.
   *
   * False also when the attribute is missing or uses a hash this program does not compute, so it
   * reads as "could not confirm" rather than as "names a different certificate".
   */
  signingCertificateBound: boolean;
}

export type TsaConfig =
  | { kind: "none" }
  | { kind: "preset"; preset: "freeTsa" | "digiCert" }
  | { kind: "custom"; url: string; rootPem?: string | null };

// --- Signing ------------------------------------------------------------------------------------

export interface SignResult {
  source: string;
  output: string;
  documentDigest: string;
  timestamp: TimestampVerification | null;
}

/**
 * Why a signature has not reached the disk.
 *
 * Held per signature rather than per run: one batch can have a file waiting on an authority and
 * another waiting on a directory that cannot be written to, and offering "再試行" for the second
 * would retry the wrong thing.
 */
export type Blocker =
  | { kind: "timestamp"; message: string }
  | { kind: "write"; message: string };

/**
 * The file the card refused, and why.
 *
 * Not a `Blocker`: nothing was produced for this file, so there is nothing to retry or discard.
 * `skipped` is the rest of the batch, which never reached the card at all.
 */
export interface SigningFailure {
  path: string;
  message: string;
  skipped: string[];
}

/**
 * A signature that exists but has not been written.
 *
 * The card has already produced it. It is held back only because `blockedBy` got in the way, and
 * the user decides what happens to it — retrying costs no card operation and no password.
 */
export interface PendingInfo {
  id: number;
  source: string;
  output: string;
  documentDigest: string;
  blockedBy: Blocker;
}

export type SideOutputKind = "publicKey" | "timestampToken";

/**
 * A file written beside a signature.
 *
 * Reported after the fact, with `written` and `error`, because the interface must not list a path
 * as an output when the write failed. A name on screen that is not a name on disk is the kind of
 * thing that is found out much later.
 */
export interface SideOutput {
  path: string;
  kind: SideOutputKind;
  written: boolean;
  /** Why it was not written. `null` when it was. */
  error: string | null;
}

export interface SignOutcome {
  written: SignResult[];
  pending: PendingInfo[];
  /** The file the card refused, when one did, and what the batch stopped short of. */
  signingError: SigningFailure | null;
  /** Public keys and `.tsr` tokens, as they actually turned out. */
  sideOutputs: SideOutput[];
  /** How many files the run was asked to sign, so a total can be shown that adds up. */
  requested: number;
}

export type PlannedKind = "signature" | "publicKey" | "timestampToken";

/**
 * A file `sign_files` would write.
 *
 * Asked of the Rust side rather than worked out here: the naming rule already lives there and in
 * the CLI, and a third copy in the window would drift from both.
 */
export interface PlannedOutput {
  /** The file this comes from, when it comes from one. */
  source: string | null;
  path: string;
  kind: PlannedKind;
  /** Something is already there and will be replaced. */
  exists: boolean;
}

/**
 * What to do with a signature that has not been written.
 *
 * `writeTo` carries paths that came from a save dialog. The page never composes them: a path
 * chosen in the window would be a path the user did not agree to write.
 */
export type PendingAction =
  | "retry"
  | "writeWithoutTimestamp"
  | "discard"
  | { writeTo: { outputs: string[] } };

/** Where a signing run has got to. */
export interface Progress {
  index: number;
  total: number;
  path: string;
  /** `timestamping` only ever while a request is actually out to an authority. */
  stage: "signing" | "timestamping" | "writing" | "done";
}

/** What `sign_files` and `plan_outputs` are both asked. */
export interface PgpRequest {
  paths: string[];
  embedCertificate: boolean;
  exportPublicKey: boolean;
  cleartext: boolean;
  writeTsr: boolean;
  tsa: TsaConfig;
}

// --- Errors -------------------------------------------------------------------------------------

/**
 * Errors as the interface sees them.
 *
 * Split by kind so the window can react — offer to connect, keep a retry count, name a file —
 * rather than read the message and guess. Nothing here is ever decided by matching on prose: a
 * message is for the person, and the kind is for the program.
 */
export type AppError =
  | { kind: "card"; message: string }
  | { kind: "pinIncorrect"; retries: number | null }
  | { kind: "pinBlocked" }
  | { kind: "notConnected" }
  | { kind: "cardRemoved" }
  | { kind: "io"; operation: string; detail: string }
  | { kind: "notText"; path: string }
  | { kind: "failed"; message: string };

/** The kinds Rust can send. Anything else is not an `AppError`, whatever fields it happens to have. */
const KINDS = new Set<AppError["kind"]>([
  "card",
  "pinIncorrect",
  "pinBlocked",
  "notConnected",
  "cardRemoved",
  "io",
  "notText",
  "failed",
]);

const basename = (path: string) => path.split(/[\\/]/).pop() ?? path;

/**
 * Turn any thrown value into the shape the interface reacts to.
 *
 * The discriminant is checked against the kinds that exist, so a rejection that is some other
 * object with a `kind` field does not get treated as an error this program knows how to explain.
 */
export function asAppError(error: unknown): AppError {
  if (error && typeof error === "object" && "kind" in error) {
    const kind = (error as { kind: unknown }).kind;
    if (typeof kind === "string" && KINDS.has(kind as AppError["kind"])) {
      return error as AppError;
    }
  }
  if (error instanceof Error) return { kind: "failed", message: error.message };
  return { kind: "failed", message: String(error) };
}

/**
 * A sentence for an error, in the language of the interface.
 *
 * Every kind Rust distinguishes ends by saying what to do about it, because an error the reader
 * cannot act on is just a closed door. `failed` is the exception and is passed through as it
 * arrived: it is the kind that means "something Rust could not classify either", and inventing a
 * next step for it would be inventing a diagnosis.
 */
export function describe(error: AppError): string {
  switch (error.kind) {
    case "pinBlocked":
      return PIN_BLOCKED.sentence;
    case "pinIncorrect":
      return error.retries === null
        ? "署名用パスワードが違います。カードは残り回数を報告しませんでした。"
        : `署名用パスワードが違います。残り ${error.retries} 回でロックされます。`;
    case "notConnected":
      return "カードが接続されていません。「カード」画面で接続してください。";
    case "cardRemoved":
      return "カードが応答しなくなりました。リーダーに正しく載っているか確認して、もう一度接続してください。";
    case "card":
      return `カードとのやり取りに失敗しました。（${error.message}）カードがリーダーに正しく載っているか確認して、もう一度試してください。`;
    case "io":
      return `${error.operation}に失敗しました。（${error.detail}）`;
    case "notText":
      return `${basename(error.path)} はテキストではないため、クリアテキスト署名にできません。「クリアテキスト署名にする」を外すか、別のファイルを選んでください。`;
    case "failed":
      return error.message;
  }
}

export const api = {
  listReaders: () => invoke<string[]>("list_readers"),
  connect: (reader: string | null) => invoke<CardStatus>("connect", { reader }),
  disconnect: () => invoke<void>("disconnect"),
  authCertificate: () => invoke<CertificateInfo>("auth_certificate"),
  /** Attempts left, without spending one. Asked before every unlock — see DESIGN §11.6. */
  signPinRetries: () => invoke<number | null>("sign_pin_retries"),
  unlock: (password: string) => invoke<CertificateInfo>("unlock", { password }),

  signFiles: (request: PgpRequest) =>
    invoke<SignOutcome>("sign_files", { request }),

  /** What `signFiles` would write, without touching the card and without writing anything. */
  planOutputs: (request: PgpRequest) =>
    invoke<PlannedOutput[]>("plan_outputs", { request }),

  signPdf: (request: {
    path: string;
    output: string;
    reason: string | null;
    location: string | null;
    invisible: boolean;
    appearance: {
      page: number;
      rect: [number, number, number, number];
      imagePath: string | null;
    } | null;
    tsa: TsaConfig;
  }) => invoke<SignOutcome>("sign_pdf", { request }),

  resolvePending: (ids: number[], action: PendingAction) =>
    invoke<SignOutcome>("resolve_pending", { ids, action }),

  listPending: () => invoke<PendingInfo[]>("list_pending"),

  /**
   * Stop asking authorities for the rest of this run.
   *
   * Between items only. A request already in flight is left to finish, because abandoning it would
   * mean not knowing whether the token that comes back was ever issued.
   */
  cancelTimestamping: () => invoke<void>("cancel_timestamping"),

  testTsa: (config: TsaConfig) =>
    invoke<TimestampVerification>("test_tsa", { config }),

  verifyDetached: (
    signaturePath: string,
    documentPath: string,
    acceptTestHierarchy: boolean,
  ) =>
    invoke<PgpVerification>("verify_detached", {
      signaturePath,
      documentPath,
      acceptTestHierarchy,
    }),

  verifyPdf: (path: string, acceptTestHierarchy: boolean) =>
    invoke<PdfSignatureVerification[]>("verify_pdf", {
      path,
      acceptTestHierarchy,
    }),

  /**
   * Write a verification result out as plain text.
   *
   * The lines are the ones on screen — see `claims.ts`. The header and the disclaimer are added on
   * the Rust side so that no caller can leave them off.
   */
  exportVerification: (path: string, lines: string[]) =>
    invoke<void>("export_verification", { path, lines }),

  documentDigest: (path: string) => invoke<string>("document_digest", { path }),

  /** Raw bytes, for the placement view to render. The window has no filesystem access of its own. */
  readFile: (path: string) => invoke<ArrayBuffer>("read_file", { path }),

  /** The panel that will be drawn on the page when the signer supplies no image of their own. */
  previewSignaturePanel: (reason: string | null, location: string | null) =>
    invoke<ArrayBuffer>("preview_signature_panel", { reason, location }),

  /** Where the signature goes if the signer places it nowhere. */
  defaultSignaturePlacement: (
    path: string,
    imagePath: string | null,
    reason: string | null,
    location: string | null,
  ) =>
    invoke<{ page: number; rect: [number, number, number, number] }>(
      "default_signature_placement",
      { path, imagePath, reason, location },
    ),
};
