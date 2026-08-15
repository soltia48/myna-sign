/**
 * How a verification result is shown.
 *
 * There is no green tick that means "valid", because this program cannot establish that. It can
 * establish that a signature verifies, that a chain reaches a J-LIS root, that a timestamp says
 * the signature existed at a given moment — and it cannot establish that the certificate was not
 * revoked, because that needs an online service it does not consult.
 *
 * So the result is a list of separate claims, each with its own state, and "失効確認" is always
 * present and always says 未実施. A single verdict would have to be either a lie or a refusal.
 *
 * The four groups are that refusal made legible; they do not soften it. A dozen lines in one
 * typeface invite the reader to do the arithmetic the program will not do — count the ticks and
 * arrive at the single verdict anyway — and they leave §7.4's one reservation sitting eighth in
 * the list, in the colour reserved for asides. Sorting the same claims by what the reader has to
 * do about them gives that reservation a heading of its own. No heading carries a count: "(5)/(2)"
 * is a score, and a score is the single verdict wearing another coat.
 *
 * Nothing here puts a person's name on screen on the strength of a signature that does not bind
 * the document in hand. A PDF's CMS signature is made over `signedAttrs`, so rewriting a byte of
 * the page leaves `signatureVerified` true and only `documentDigestMatches` false; the name shown
 * then would be the name of somebody who signed something else.
 */
import { Fragment } from "preact";
import { useId } from "preact/hooks";
import {
  describeSex,
  describeSubstitutes,
  substitutePositions,
  type CertificateInfo,
  type Substitutes,
  type TimestampVerification,
  type TrustCheck,
} from "../lib/api";
import {
  timestampClaim,
  TONE_WORDS,
  trustClaims,
  type ClaimLine,
  type Tone,
} from "../lib/claims";

export function Claim({
  label,
  tone,
  state,
  children,
}: {
  label: string;
  tone: Tone;
  /**
   * The state word to announce. Left out, the tone supplies it; `null` silences it, for the places
   * where the tone is typography rather than a verdict and "問題なし" would be a claim of its own.
   */
  state?: "問題なし" | "要注意" | "問題あり" | "未確認" | null;
  children: preact.ComponentChildren;
}) {
  const mark = { ok: "✓", warn: "!", bad: "✗", unknown: "?" }[tone];
  // The mark is a glyph, a colour and `aria-hidden`, so without a word here a failed check reads
  // as "署名の検証 一致しません" in the same voice as a passing one. The words come from
  // `claims.ts` because the exported text file labels its lines with the same four, and a screen
  // and a file that disagree about what was found are worse than either alone.
  const spoken = state === undefined ? TONE_WORDS[tone] : state;
  return (
    <div class={`claim claim-${tone}`}>
      <span class="claim-mark" aria-hidden="true">
        {mark}
      </span>
      {/*
        The state rides inside the label rather than beside it: `.claim` is a three-column grid,
        and a fourth child would drop to a row of its own the day `.visually-hidden` is written
        without taking the element out of flow. The ideographic space is a pause, not punctuation
        a reader has to hear read out.
      */}
      <span class="claim-label">
        {spoken !== null && <span class="visually-hidden">{spoken}　</span>}
        {label}
      </span>
      <span class="claim-value">{children}</span>
    </div>
  );
}

/**
 * Labels this file has to recognise, spelled the way `claims.ts` spells them.
 *
 * Two decisions below turn on which claim a line is, and a `ClaimLine` carries only its wording.
 * Matching the label leaves the vocabulary in the one place the contract puts it rather than
 * growing a second description of every claim here, to be kept in step by hand. A label that
 * stops matching costs the container or the silence and nothing more: no line is dropped, no line
 * changes its state, no line changes its wording.
 */
const LABEL = {
  timestamp: "タイムスタンプ",
  chain: "証明書チェーン",
  reference: "判定基準日",
  revocation: "失効確認",
  claimedTime: "署名時刻（自己申告）",
  claimedName: "署名欄の名前（自己申告）",
  reason: "理由（自己申告）",
  location: "場所（自己申告）",
} as const;

/**
 * Facts about the signature and the certificate which, once nothing binds that signature to the
 * document on screen, are not facts about that document at all — together with the four things
 * the signer wrote down themselves, which were never facts about anything else either.
 */
const SAYS_NOTHING_ABOUT_THIS_DOCUMENT: readonly string[] = [
  LABEL.timestamp,
  LABEL.chain,
  LABEL.reference,
  LABEL.revocation,
  LABEL.claimedTime,
  LABEL.claimedName,
  LABEL.reason,
  LABEL.location,
];

/**
 * Claims where the tone is a typeface and not a finding: the signer wrote these into the file, and
 * this program neither checked them nor disputes them. Their labels already say 自己申告, and
 * announcing a state as well would report a finding the verification never made.
 */
const NO_STATE_TO_ANNOUNCE: readonly string[] = [
  LABEL.claimedTime,
  LABEL.claimedName,
  LABEL.reason,
  LABEL.location,
];

/**
 * In the order they are drawn: what failed, what to look at, what held, what was never looked at.
 * The tone doubles as the identity of the group, so there is no second table of group membership
 * to drift out of step with the one in `claims.ts`.
 */
const GROUPS: readonly { tone: Tone; heading: string }[] = [
  { tone: "bad", heading: "この署名は検証できませんでした" },
  { tone: "warn", heading: "注意が必要なこと" },
  { tone: "ok", heading: "確認できたこと" },
  { tone: "unknown", heading: "この検証で確認していないこと" },
];

/**
 * The claims of one verification, sorted into the four groups.
 *
 * `warn` is a group and not a shade of `ok` because what lands in it — a test hierarchy, which is
 * not a real person; a reference date taken from the clock, which expires with the certificate; a
 * revision appended after signing — reads as "確認できたこと" nowhere but in a summary that has
 * given up on the difference.
 */
export function VerdictGroups({
  claims,
  bound = true,
}: {
  claims: ClaimLine[];
  /**
   * Whether the signature binds this document, on the same terms as `Signer`. False moves the
   * claims that only ever described the signature into a container that says so. It defaults to
   * true because the container is itself an assertion: a caller that has not said must not have
   * one invented for it.
   */
  bound?: boolean;
}) {
  const id = useId();
  return (
    <>
      {GROUPS.map(({ tone, heading }) => {
        const lines = claims.filter((line) => line.tone === tone);
        // Every group but the last appears only when something is in it. The last appears always:
        // 失効確認 belongs to it, and so does the sentence below it, which is the one thing this
        // screen has to say whatever the file turned out to be (§7.4).
        if (lines.length === 0 && tone !== "unknown") return null;
        const detached = bound ? [] : lines.filter(saysNothingAboutThisDocument);
        const attributed = bound
          ? lines
          : lines.filter((line) => !saysNothingAboutThisDocument(line));
        return (
          <div
            class={`verdict-group g-${tone}`}
            role="group"
            aria-labelledby={`${id}-${tone}`}
            key={tone}
          >
            <h3 class="verdict-group-head" id={`${id}-${tone}`}>
              {heading}
            </h3>
            {attributed.map(claimOf)}
            {detached.length > 0 && (
              /*
                The ticks inside stay ticks. The timestamp really did verify, and the chain really
                did reach a root; rewriting them as question marks would be a second untruth told
                to make up for the first. What is wrong is not the state of these checks but what a
                reader takes them to be about, and that is what the container corrects. It does not
                fold away, either: 失効確認 is in here whenever the document is unbound, and §7.4
                asks for that line on every result, not on every result the reader thinks to open.

                The sentence is the container's heading rather than a note under it: it changes
                what everything below it means, which is not the work of an aside. `h4` because the
                group heading above is `h3` and this sits inside it; the styling rides on the class.
              */
              <div class="unattributed">
                <h4 class="verdict-group-head">
                  これらは署名と証明書についての事実で、この文書については何も示していません
                </h4>
                {detached.map(claimOf)}
              </div>
            )}
            {tone === "unknown" && (
              /*
                Body text, deliberately not `.note`. Setting this in the size and colour kept for
                asides is how the reservation went missing in the first place; it is the sentence
                the reader has to leave with.
              */
              <p>
                本アプリは失効情報サービスを参照しません。証明書が失効していても、この画面の表示は変わりません。
              </p>
            )}
          </div>
        );
      })}
    </>
  );
}

function saysNothingAboutThisDocument(line: ClaimLine): boolean {
  return SAYS_NOTHING_ABOUT_THIS_DOCUMENT.includes(line.label);
}

function claimOf(line: ClaimLine, index: number) {
  // §7.4 requires a badge wherever a test hierarchy was accepted, and a qualified chain claim is
  // the only line that can carry one. The wording is still `claims.ts`'s — what is decided here is
  // the emphasis, which is a property of the screen and of nothing that gets exported.
  const badge = line.label === LABEL.chain && line.tone === "warn";
  return (
    <Claim
      key={`${line.label}-${index}`}
      label={line.label}
      tone={line.tone}
      state={NO_STATE_TO_ANNOUNCE.includes(line.label) ? null : undefined}
    >
      {line.value}
      {line.detail &&
        (badge ? (
          <strong class="badge-test">{line.detail}</strong>
        ) : (
          <small class="chain">{line.detail}</small>
        ))}
    </Claim>
  );
}

/**
 * The certificate's standing: the chain, the date it was judged on, and revocation.
 *
 * The sentences are `claims.ts`'s, because the exported text file is made of the same ones and two
 * spellings of "失効確認 — 未実施" would be two things to keep true at once. This renders them
 * where a caller wants the three claims on their own rather than sorted into groups.
 */
export function TrustClaims({ trust }: { trust: TrustCheck | null }) {
  return <>{trustClaims(trust).map(claimOf)}</>;
}

/** The timestamp, as one claim, in the same words the verification screen and the file use. */
export function TimestampClaim({
  timestamp,
}: {
  timestamp: TimestampVerification | null;
}) {
  return claimOf(timestampClaim(timestamp), 0);
}

/**
 * A field of the certificate with its substituted characters marked where they stand.
 *
 * "3、5 文字目に代替文字が使われています" leaves the reader counting, and a name whose parts are
 * divided by an ideographic space is exactly where the count goes wrong — that space is a
 * character and the flags count it. The sentence stays: it is what a screen reader gets, and what
 * survives being copied out of the window. The marks say the same thing to the eye.
 *
 * The string is taken apart with `Array.from` because the positions are counted in characters, as
 * `x509.rs` counts them with `chars().count()`. Indexing by `.length` would count UTF-16 units and
 * slip by one at every character outside the BMP — which is most of the rare kanji this field
 * exists to flag.
 */
function Substituted({
  text,
  substitutes,
}: {
  text: string;
  substitutes: Substitutes | null;
}) {
  // `substitutePositions` refuses when the flags describe a different number of characters than
  // the field has: those positions are not positions in this text, and marking by them would put
  // the warning on innocent characters while leaving the substituted one bare. The sentence from
  // `describeSubstitutes` reports the mismatch instead, and nothing here is underlined.
  const positions = substitutePositions(substitutes);
  if (!positions || positions.length === 0) {
    return <>{text}</>;
  }
  const substituted = new Set(positions);
  return (
    <>
      {Array.from(text).map((character, index) =>
        substituted.has(index + 1) ? (
          <span class="substitute-mark" key={index}>
            {character}
          </span>
        ) : (
          character
        ),
      )}
    </>
  );
}

/**
 * The signer, as the certificate names them.
 *
 * Shown only where something binds the signature to the document in hand — otherwise this is
 * somebody else's certificate stapled to somebody else's signature, and putting a name on screen
 * would be naming the wrong person. For a PDF that takes the document digest and the byte range
 * as well as the signature: the CMS signature is made over `signedAttrs` and survives an edit to
 * the page it is supposed to cover, so `signatureVerified` alone would put a real name, address,
 * date of birth and sex under a tampered document.
 */
export function Signer({
  certificate,
  bound,
  unboundReason,
}: {
  certificate: CertificateInfo | null;
  bound: boolean;
  /**
   * The whole sentence shown in place of the name, from a caller that knows which check failed.
   * It has to say both why and that the name is being withheld.
   */
  unboundReason?: string | null;
}) {
  if (!certificate) return null;
  if (!bound) {
    // The sentence this used to give unconditionally — 署名が検証できないため — is false in the
    // case that matters most: a tampered PDF whose CMS signature verifies perfectly well. The
    // fallback now says only what `bound` being false actually means in every one of its cases,
    // and a caller with a specific reason replaces it with the specific one.
    return (
      <Claim label="署名者" tone="bad">
        {unboundReason ??
          "この証明書の名義人がこの文書に署名したことを確認できないため、氏名は表示しません"}
      </Claim>
    );
  }
  const holder = certificate.holder;
  const substitutions = [
    describeSubstitutes("氏名", holder.nameSubstitutes),
    describeSubstitutes("住所", holder.addressSubstitutes),
  ].filter((s): s is string => s !== null);
  return (
    <div class="signer">
      {/*
        A substitute is a warning and not a fault, including when the flags do not line up with the
        field: nothing here is evidence that the certificate is broken, only that its text and the
        register's differ, or that this certificate is not laid out the way the program expects.
      */}
      <Claim label="署名者" tone={substitutions.length > 0 ? "warn" : "ok"}>
        {holder.name ? (
          <Substituted text={holder.name} substitutes={holder.nameSubstitutes} />
        ) : (
          (certificate.commonName ?? certificate.subject)
        )}
        {substitutions.map((text) => (
          <small class="chain" key={text}>
            {text}
          </small>
        ))}
      </Claim>
      <dl class="holder">
        {holder.address && (
          <>
            <dt>住所</dt>
            <dd>
              <Substituted text={holder.address} substitutes={holder.addressSubstitutes} />
            </dd>
          </>
        )}
        {holder.birthDate && (
          <>
            <dt>生年月日</dt>
            <dd>{holder.birthDate}</dd>
          </>
        )}
        {holder.sex && (
          <>
            <dt>性別</dt>
            <dd>{describeSex(holder.sex)}</dd>
          </>
        )}
        <dt>証明書の有効期間</dt>
        <dd>
          {certificate.notBefore} 〜 {certificate.notAfter}
        </dd>
        <dt>フィンガープリント</dt>
        <dd>
          <code>{certificate.fingerprint.slice(0, 32)}…</code>
        </dd>
        {/* Keyed on the pair, not on the two cells inside it: the key on a `<dt>` inside an
            unkeyed fragment never reaches the list this is reconciled as. */}
        {holder.other.map(([oid, value]) => (
          <Fragment key={oid}>
            <dt>{oid}</dt>
            <dd>{value}</dd>
          </Fragment>
        ))}
      </dl>
    </div>
  );
}
