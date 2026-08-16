/**
 * The signature password.
 *
 * Four things this screen does that a plain prompt would not:
 *
 * - it shows **what is about to be signed**, by name and by digest, because a signing certificate
 *   carries legal weight and "I did not realise I was signing that" must not be possible;
 * - it shows **what the signature hands over**, because the signing certificate carries the
 *   holder's name, address, date of birth and sex, and this is the last moment at which learning
 *   that can still change the answer;
 * - it names **where a timestamp request would go**, since that is the only thing this window ever
 *   sends anywhere; and
 * - it shows **how many attempts are left**, and asks again when the next one may be the last,
 *   because the fifth wrong password blocks the key until the holder visits a municipal office.
 *
 * It is a real `<dialog>` opened with `showModal`. That is not decoration: it is what makes the
 * rest of the window inert. Without it the tab order still reaches the destructive buttons behind
 * the scrim, so a keyboard could discard a signing run that this dialog is in the middle of
 * authorising, while a mouse could not.
 *
 * The password lives in this component's local state and nowhere else. It is cleared on unmount
 * and on submit.
 */
import { Fragment, type ComponentChildren } from "preact";
import { useEffect, useRef, useState } from "preact/hooks";

import { api, asAppError, describe, type CertificateInfo } from "../lib/api";

export interface SigningSubject {
  /** What is about to be signed, one line each. */
  label: string;
  /** SHA-256 of it, hex. */
  digest: string;
}

/**
 * What this particular signature will disclose, and by which route.
 *
 * The routes differ but the payload does not: every one of them carries the basic four. The shape
 * is per-format rather than a list of flags so that a caller cannot describe a PDF that leaves the
 * certificate out — there is no such PDF.
 */
export type Disclosure =
  | { kind: "pdf"; nameOnPage: boolean; publicKey: false }
  | { kind: "pgp"; embed: boolean; publicKey: boolean; publicKeyName: string | null };

interface Props {
  subjects: SigningSubject[];
  retries: number | null;
  disclosure: Disclosure;
  /** Where the 32-byte hash would go, or null when nothing leaves the machine. */
  tsaDestination: string | null;
  /** Called with the 署名用証明書, which the password is what unlocks. */
  onUnlocked: (certificate: CertificateInfo) => void;
  onCancel: () => void;
  /** Every number the card reports, so the count outlives this dialog. */
  onRetriesObserved: (retries: number) => void;
}

interface DisclosureLine {
  term: string;
  body: ComponentChildren;
}

/**
 * The sentences about what leaves this machine, in the order they happen.
 *
 * The wording never generalises: it names the file that carries the certificate, and it says
 * "外せません" only where that is true. The four fields are marked up rather than spelled into a
 * word like "個人情報", because "住所" is the one that changes people's minds.
 */
function disclosureLines(
  disclosure: Disclosure,
  tsaDestination: string | null,
): DisclosureLine[] {
  const basics = <strong>氏名・住所・生年月日・性別</strong>;
  const lines: DisclosureLine[] = [];

  if (disclosure.kind === "pdf") {
    lines.push({
      term: "PDF",
      body: (
        <>この PDF には署名用電子証明書が必ず入ります — {basics}が相手に開示されます（外せません）。</>
      ),
    });
    if (disclosure.nameOnPage) {
      lines.push({
        term: "ページ上の署名欄",
        // Said here and in general terms because it has to be said before the password: the
        // certificate is what carries the substitutes, and it is not readable until afterwards.
        // The specific characters are marked on the card screen once it has been read.
        body: (
          <>
            さらに、ページ上の署名欄に<strong>氏名と住所</strong>が印字されます。証明書の表記には
            戸籍と異なる代替文字が使われていることがあります。
          </>
        ),
      });
    }
  } else {
    lines.push({
      term: "署名ファイル（.asc）",
      body: disclosure.embed ? (
        <>.asc に署名用電子証明書を埋め込みます — {basics}が相手に開示されます。</>
      ) : (
        "証明書は埋め込みません。相手は別途あなたの証明書を受け取らないと検証できません。"
      ),
    });
  }

  // Outside the branch above on purpose. A public key carries the holder's name in its User ID
  // whether or not the signature embeds the certificate, so leaving this line under the PGP arm
  // would let "証明書は埋め込みません" read as "nothing about me goes out", which is false.
  if (disclosure.publicKey) {
    lines.push({
      term: "公開鍵ファイル",
      body: disclosure.publicKeyName ? (
        <>
          併せて書き出す <code>{disclosure.publicKeyName}</code> の User ID に氏名が入ります。
        </>
      ) : (
        "併せて書き出す公開鍵ファイルの User ID に氏名が入ります。"
      ),
    });
  }

  // Sits in the same list rather than in a block of its own: at the moment of deciding, what
  // leaves this machine is one question, and a second box would only compete with the first.
  lines.push({
    term: "外部通信",
    body:
      tsaDestination === null ? (
        "外部へは何も送信しません。"
      ) : (
        <>
          送信先: <code>{tsaDestination}</code>。送るのは署名のハッシュ 32
          バイトだけで、文書は送りません。
        </>
      ),
  });

  return lines;
}

/**
 * Why this value cannot be the password on the card, when it cannot.
 *
 * The card allows five wrong attempts and then only a municipal counter can unlock the key, so
 * anything that could not possibly be right is refused here instead of being spent on an attempt.
 * The rules are the ones the signature password is registered under: six to sixteen characters,
 * digits and uppercase letters. `myna_card::Pin` is looser (any printable ASCII) because it speaks
 * for every secret on the card, including the four-digit ones.
 */
function unusable(password: string): string | null {
  if (/[a-z]/.test(password)) {
    return "英字は大文字で入力してください。署名用パスワードは大文字で登録されています。";
  }
  if (!/^[A-Z0-9]*$/.test(password)) {
    return "使えるのは英数字（A〜Z と 0〜9）だけです。";
  }
  if (password.length < 6 || password.length > 16) {
    return "署名用パスワードは 6〜16 文字です。";
  }
  return null;
}

export function PasswordDialog({
  subjects,
  retries,
  disclosure,
  tsaDestination,
  onUnlocked,
  onCancel,
  onRetriesObserved,
}: Props) {
  const [password, setPassword] = useState("");
  const [reveal, setReveal] = useState(false);
  const [busy, setBusy] = useState(false);
  /** What the card said, and whether that sentence is already the one carrying the count. */
  const [error, setError] = useState<{ text: string; withCount: boolean } | null>(null);
  const [invalid, setInvalid] = useState<string | null>(null);
  const [remaining, setRemaining] = useState(retries);
  const [confirmed, setConfirmed] = useState(false);
  const dialog = useRef<HTMLDialogElement>(null);
  const input = useRef<HTMLInputElement>(null);

  /**
   * Put the caret in the field, and the field somewhere it can be seen.
   *
   * The field sits outside the scrolling part of the dialog, so it is always in view and the
   * scroll here is normally none. `preventScroll` is still what makes that true: focusing without
   * it lets the engine scroll an ancestor to satisfy itself, and the one time that had somewhere
   * to go it took the title and "以下に電子署名します。" off the top of the box.
   */
  function focusPassword() {
    const node = input.current;
    if (!node) return;
    node.focus({ preventScroll: true });
    node.scrollIntoView({ block: "nearest" });
  }

  useEffect(() => {
    const node = dialog.current;
    if (node && !node.open) {
      // An engine without `showModal` would leave the element at `display: none` and the window
      // waiting on a dialog nobody can see, so it is opened either way; only the inertness of the
      // page behind is lost.
      if (typeof node.showModal === "function") node.showModal();
      else node.open = true;
    }
    focusPassword();
    return () => {
      // Nothing keeps the password after this component goes away.
      setPassword("");
      // A modal taken out of the document while still open has been known to leave the rest of the
      // page inert, which would lock the window with no dialog on screen to explain it.
      if (node?.open) node.close();
    };
  }, []);

  // A count of one means the next mistake blocks the key. No count means the card did not say how
  // many have already been spent, which could equally well be four — so the unknown is treated as
  // the dangerous case rather than the harmless one.
  const needsConfirmation = remaining === 1 || remaining === null;
  const blocked = remaining === 0;
  const problem = error?.text ?? invalid;

  // When `describe` has already named the number of attempts left, it is not said again here: one
  // sentence carrying it means one announcement, and no chance of the two disagreeing. Errors that
  // say nothing about the count — a card pulled out of the reader — leave it standing.
  const status = error?.withCount
    ? ""
    : (blocked
        ? "ロック済み。市区町村の窓口でのみ解除できます。"
        : remaining === null
          ? "カードは残り回数を報告していません。"
          : `残り ${remaining} 回。`) +
      (needsConfirmation && confirmed && !busy
        ? remaining === 1
          ? "次に間違えるとロックされます。本当に送信しますか？"
          : "何回間違えているか分からないため、次でロックされるかもしれません。本当に送信しますか？"
        : "");

  async function submit(event: Event) {
    event.preventDefault();
    if (busy || blocked) return;

    const refused = unusable(password);
    if (refused) {
      // Checked before the confirmation below: a value the card would refuse anyway is not a
      // decision worth confirming, and this way it costs no attempt.
      setInvalid(refused);
      setError(null);
      focusPassword();
      return;
    }
    setInvalid(null);

    if (needsConfirmation && !confirmed) {
      setConfirmed(true);
      return;
    }

    setBusy(true);
    setError(null);
    // The password is on its way to the card; it has no reason to stay legible on screen.
    setReveal(false);
    try {
      const certificate = await api.unlock(password);
      setPassword("");
      onUnlocked(certificate);
    } catch (thrown) {
      const failure = asAppError(thrown);
      setError({
        text: describe(failure),
        withCount: failure.kind === "pinIncorrect" || failure.kind === "pinBlocked",
      });
      if (failure.kind === "pinIncorrect") {
        setRemaining(failure.retries);
        // `null` means the card did not say, not that nothing is left. Passing it on would erase a
        // number that is still the best thing anyone knows.
        if (failure.retries !== null) onRetriesObserved(failure.retries);
      }
      if (failure.kind === "pinBlocked") {
        setRemaining(0);
        onRetriesObserved(0);
      }
      // Each attempt costs one of five, so the next one is confirmed again rather than riding on a
      // confirmation given for the attempt that has just been spent.
      setConfirmed(false);
      setPassword("");
      focusPassword();
    } finally {
      setBusy(false);
    }
  }

  function escaped(event: Event) {
    // Always prevented, because the caller owns whether this component exists: letting the browser
    // close the element would leave an invisible dialog mounted and the screen behind it waiting.
    event.preventDefault();
    // A request already at the card resolves into `onUnlocked`, so closing now would produce a
    // signature that the holder believes they cancelled.
    if (busy) return;
    onCancel();
  }

  return (
    // Clicking beside the dialog deliberately does nothing. The usual "click the backdrop to
    // dismiss" would put cancelling a signature one stray click away, and the cancel button is
    // right there.
    <div class="scrim">
      <dialog
        ref={dialog}
        class="dialog"
        aria-modal="true"
        aria-labelledby="pw-title"
        aria-describedby="pw-disclosure"
        onCancel={escaped}
        // The user agent draws `dialog` as a bordered box in its own colours, and the sheet
        // dresses `.dialog` without saying anything about the element. `inset` is here so the box
        // is centred by its own margins whether or not the engine styles a modal for us.
        style={{ border: "none", color: "var(--text)", inset: "0" }}
      >
        <form onSubmit={submit}>
          <h2 id="pw-title">署名用パスワード</h2>

          {/* The only part that scrolls. Everything outside it — the title, the field, the attempt
              count, the buttons — stays where it is at any window size the application allows. */}
          <div class="dialog-body">
          <section class="subject">
            <p class="subject-lead" id="pw-subject-lead">
              以下に電子署名します。
            </p>
            {/* Ten files must not turn the dialog into a page whose bottom half has to be hunted
                for: the list keeps a fixed share of the window and scrolls within it. It takes a
                tab stop of its own, because a scrolling box with no focusable children is one that
                a keyboard cannot reach the bottom of — and the bottom is a file being signed. */}
            <ul
              tabIndex={0}
              aria-labelledby="pw-subject-lead"
              style={{ maxHeight: "30vh", overflowY: "auto" }}
            >
              {subjects.map((subject) => (
                <li key={subject.digest + subject.label}>
                  <span class="subject-name">{subject.label}</span>
                  <code class="digest">SHA-256 {subject.digest.slice(0, 32)}…</code>
                </li>
              ))}
            </ul>
          </section>

          {/* No marks. ✓ and ✗ are the vocabulary of a verification result, where they report what
              was found; nothing has happened yet here, and a mark would read as a verdict on a
              decision the holder has not made. */}
          <dl class="disclosure" id="pw-disclosure">
            {/* The pairs are siblings, not wrapped in a `div` each: the stylesheet spaces the rows
                by `dd` and closes the gap on the last one, and a wrapper would make every `dd` the
                last of something. */}
            {disclosureLines(disclosure, tsaDestination).map((line) => (
              <Fragment key={line.term}>
                <dt>{line.term}</dt>
                <dd>{line.body}</dd>
              </Fragment>
            ))}
          </dl>
          </div>

          {/* The toggle stays on the input's line, and outside the label: below it, it would cost
              the vertical room the attempt count needs; inside it, its text would become part of
              the field's name. */}
          <div style={{ display: "flex", gap: "var(--sp-2)", alignItems: "flex-end" }}>
            <label class="field" style={{ flex: "1", marginBottom: 0 }}>
              <span>
                英数字 6〜16 文字（<strong>英字は大文字</strong>）
              </span>
              <input
                ref={input}
                type={reveal ? "text" : "password"}
                autocomplete="off"
                autocorrect="off"
                autocapitalize="off"
                spellcheck={false}
                value={password}
                // Read-only rather than disabled while the card is being asked: a disabled field
                // drops focus to the document body, and the focus put back after a wrong password
                // then lands nowhere.
                disabled={blocked}
                readOnly={busy}
                aria-invalid={problem ? "true" : "false"}
                aria-describedby="pw-status pw-problem"
                onInput={(e) => {
                  setPassword((e.target as HTMLInputElement).value);
                  // The old sentence described the value that has just been replaced, and the one
                  // from the card also carries a count that the status line takes back over.
                  setInvalid(null);
                  setError(null);
                }}
              />
            </label>
            <button
              type="button"
              class="ghost small"
              aria-label={reveal ? "パスワードを隠す" : "パスワードを表示"}
              onClick={() => setReveal(!reveal)}
              disabled={blocked}
            >
              {reveal ? "隠す" : "表示"}
            </button>
          </div>

          {/* Outside the scrolling part, so the attempts left and the last-attempt question — the
              two sentences that exist to stop the fifth mistake — cannot be scrolled away. */}
          <div class="dialog-foot">
            {/* Both regions are always here, empty or not. A live region added to the page at the
                same moment as its text is announced by nothing. */}
            <p
              id="pw-status"
              role="status"
              class={needsConfirmation || blocked ? "retries danger" : "retries"}
            >
              {status}
            </p>

            <div id="pw-problem" role="alert">
              {problem && <p class="error">{problem}</p>}
            </div>

            <div class="actions">
              <button type="button" class="ghost" onClick={onCancel} disabled={busy}>
                キャンセル
              </button>
              <button
                type="submit"
                class={needsConfirmation ? "danger" : ""}
                disabled={busy || blocked || password.length === 0}
              >
                {busy
                  ? "確認中…"
                  : needsConfirmation && !confirmed
                    ? "続ける"
                    : "署名する"}
              </button>
            </div>
          </div>
        </form>
      </dialog>
    </div>
  );
}
