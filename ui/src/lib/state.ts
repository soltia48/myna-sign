/**
 * Application state.
 *
 * Signals rather than a store: the state is a card session, a file selection and the options that
 * apply to them, and nothing here needs reducers or middleware to stay understandable.
 *
 * What does belong here rather than in a component is anything that must outlive a screen change.
 * The tabs unmount the screen that is not showing, so state kept in a component is state that
 * quietly resets when someone looks at another tab — and for a program that spends card retries
 * and posts to the network, "quietly reset" is a way of doing the wrong thing.
 *
 * The password is deliberately absent. It lives in the password dialog's own local state for as
 * long as it takes to submit, and nothing here ever holds it.
 */
import { signal } from "@preact/signals";

import type {
  CardStatus,
  CertificateInfo,
  PendingInfo,
  Progress,
  SideOutput,
  SignResult,
  SigningFailure,
  TsaConfig,
} from "./api";

export type Screen = "card" | "sign" | "verify" | "settings";

export const screen = signal<Screen>("card");

/** The connected card, or nothing. */
export const cardStatus = signal<CardStatus | null>(null);

/** The 署名用証明書, once the password has been presented. Carries the 基本4情報. */
export const signCertificate = signal<CertificateInfo | null>(null);

/** The 利用者証明用証明書, which needs no password. */
export const authCertificate = signal<CertificateInfo | null>(null);

/**
 * Reflects what the card last reported about the signature password.
 *
 * Call it with every number the card gives back, wherever it comes from — the count outlives the
 * dialog that observed it, and a stale figure on the card screen is what makes someone spend an
 * attempt they thought they had.
 *
 * `null` is accepted so a caller can pass the card's answer straight through, and is ignored: it
 * means the card declined to say, which is not news about the count. Overwriting a number the card
 * did report with "unknown" would throw away the only figure anyone has.
 */
export function setSignPinRetries(retries: number | null): void {
  const status = cardStatus.value;
  if (retries === null || !status || status.signPinRetries === retries) return;
  cardStatus.value = { ...status, signPinRetries: retries };
}

/** Files waiting to be signed. */
export const pending = signal<string[]>([]);

/** Where to get a timestamp. Off by default: nothing leaves the machine unasked. */
export const tsa = signal<TsaConfig>({ kind: "none" });

/**
 * The endpoint for 任意のサーバ.
 *
 * A signal, not the picker's own state: the picker is on the signing screen and on the settings
 * screen, as two instances. Held locally, the one that is not mounted knows nothing, so moving
 * between tabs leaves `tsa.value.url` set while the field on screen is empty — and the program
 * then posts 32 bytes to an address the person is not looking at. See DESIGN §9.2.
 */
export const customTsaUrl = signal("");

/**
 * Whether to accept the JPKI test hierarchy when verifying.
 *
 * Off, and it stays off unless the user turns it on for a specific reason. A test card is not a
 * person's Individual Number Card, and a result that came from one is labelled as such.
 */
export const acceptTestHierarchy = signal(false);

/** Embed the signer's certificate in OpenPGP signatures. Discloses the 基本4情報. */
export const embedCertificate = signal(true);

/** Also write the OpenPGP public key, so `gpg` can verify. */
export const exportPublicKey = signal(true);

/**
 * Put the signature inside the text rather than beside it.
 *
 * Text only. The signature then cannot be separated from what it signs, at the cost of trailing
 * whitespace, which the format cannot cover.
 */
export const cleartext = signal(false);

/** Also write the timestamp token on its own, for checking with `openssl ts -verify`. */
export const writeTsr = signal(false);

/**
 * Put nothing on the page.
 *
 * Off by default: a signature nobody can see is easy to forget is there. With it off and no image
 * chosen, a panel describing the signature is drawn instead.
 */
export const invisibleSignature = signal(false);

// --- The signing run -----------------------------------------------------------------------------

/**
 * A signing run is in flight.
 *
 * A signal, not component state. Held in the screen, leaving the tab and coming back remounts it
 * as `false`, and 「署名する」 is live again while the card is still working on the first run — so a
 * second `unlock` goes to a card mid-operation, and a mistyped password there costs a retry that
 * the person had no reason to think they were spending.
 */
export const signBusy = signal(false);

export const signProgress = signal<Progress | null>(null);

/** Signatures that reached the disk in the last run. */
export const signResults = signal<SignResult[]>([]);

/** Public keys and `.tsr` tokens, as they actually turned out — written or not. */
export const signSideOutputs = signal<SideOutput[]>([]);

/**
 * Signatures made but not written, as the screen last saw them.
 *
 * A copy for display. The signatures themselves are held in Rust, which is the one place they
 * exist: this list is what to draw, never what to decide from. Anything acting on them sends the
 * ids to `resolve_pending` and takes the new list from the outcome, so there is no second copy
 * that can disagree with the first about what is still waiting.
 */
export const signPendingBlocked = signal<PendingInfo[]>([]);

/** The file the card refused in the last run, and what that stopped the batch short of. */
export const signingFailure = signal<SigningFailure | null>(null);

/**
 * How the signature is to be placed on a PDF.
 *
 * Lifted out of the screen so that a half-configured placement survives a look at another tab.
 */
export interface PdfOptions {
  reason: string;
  location: string;
  imagePath: string | null;
  page: number;
  rect: [number, number, number, number] | null;
  /** Whether the signer chose this spot, as opposed to it being the default. */
  placed: boolean;
}

export const pdfOptions = signal<PdfOptions>({
  reason: "",
  location: "",
  imagePath: null,
  page: 1,
  rect: null,
  placed: false,
});

/**
 * Forget where the signature was put.
 *
 * Must be called whenever the file selection changes. A rectangle placed on one PDF says nothing
 * about the next one — pages differ in size and in what is printed on them — and `placed` staying
 * true also stops the default placement being asked for again, so the box would silently stay on
 * coordinates chosen for a document nobody is looking at any more. Now that this survives a screen
 * change, so would the mistake.
 *
 * The reason, the location and the image are left alone: those are about the signer, not about
 * where on a particular page they landed.
 */
export function resetPdfPlacement(): void {
  pdfOptions.value = { ...pdfOptions.value, page: 1, rect: null, placed: false };
}

// --- Messages ------------------------------------------------------------------------------------

/**
 * A one-line message at the top of the window.
 *
 * `seq` distinguishes one notice from the next. A live region announces a change in its content,
 * so notifying twice with the same words — two files failing the same way, one after the other —
 * produces no change and is read out once. The sequence number changes even when the text does
 * not, giving the region something to announce.
 */
export const banner = signal<{
  seq: number;
  tone: "info" | "warn" | "error";
  text: string;
} | null>(null);

let notices = 0;

export function notify(tone: "info" | "warn" | "error", text: string) {
  notices += 1;
  banner.value = { seq: notices, tone, text };
}

/**
 * Forget the card and everything that came off it.
 *
 * `signBusy` is deliberately not touched: a run that is under way does not stop because the card
 * went away, and clearing the flag here would put 「署名する」 back within reach while the earlier
 * run is still in the middle of things.
 */
export function clearCard() {
  cardStatus.value = null;
  signCertificate.value = null;
  authCertificate.value = null;
}
