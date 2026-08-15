/**
 * The words a verification result is made of.
 *
 * The screen and the exported text file describe the same signature, and the only way they keep
 * saying the same thing is by reading the sentences from one place. §7.4 of the design is a
 * promise about wording — the failure mode is a line that claims more than was checked — so the
 * wording is treated as the thing being maintained, rather than as a detail of whichever
 * component happens to render it.
 *
 * Nothing here produces a verdict, a count or a score. A verification is a list of separate
 * claims, each carrying its own state, and a reader who wants a single answer has to read them.
 */
import {
  describeSex,
  describeSubstitutes,
  formatJst,
  type CertificateInfo,
  type PdfSignatureVerification,
  type PgpVerification,
  type TimestampVerification,
  type TrustCheck,
} from "./api";

export type Tone = "ok" | "warn" | "bad" | "unknown";

/**
 * What a tone means, in words.
 *
 * A tone reaches the eye as a colour and a mark. Anyone reading with a screen reader, or reading
 * the exported file, needs the same distinction in text — and it has to be the same four words in
 * both places, or the file and the screen disagree about what was found.
 */
export const TONE_WORDS = {
  ok: "問題なし",
  warn: "要注意",
  bad: "問題あり",
  unknown: "未確認",
} as const satisfies Record<Tone, string>;

export interface ClaimLine {
  tone: Tone;
  /** What is being claimed about. */
  label: string;
  /** What is claimed about it. A statement, never a verdict word on its own. */
  value: string;
  /** The qualification — what the claim does not cover, or why it is not better than it is. */
  detail?: string;
  /**
   * A label to fold `detail` behind on screen, for provenance nobody reads every time.
   *
   * Only for detail that answers "where did this come from", never for detail that qualifies the
   * claim: a reservation the reader has to open is a reservation most readers never see, which is
   * the failure §7.4 is about. The written report ignores this and prints the detail either way —
   * a file has no fold, and the person reading one is looking for exactly this kind of thing.
   */
  detailSummary?: string;
}

// --- The pieces shared by both kinds of signature ------------------------------------------------

/**
 * The timestamp, as one claim.
 *
 * Exported on its own because the signing screen shows it too: a signature that has just been
 * written gets the same sentence about its timestamp as one that has just been verified.
 */
export function timestampClaim(
  timestamp: TimestampVerification | null,
): ClaimLine {
  if (!timestamp) {
    return {
      tone: "warn",
      label: "タイムスタンプ",
      value: "なし",
      detail: "証明書の有効期限が切れると、署名時点で有効だったことを示せなくなります。",
    };
  }
  if (!timestamp.verified) {
    // Ordered so the first thing that is wrong is the thing reported. The extended key usage is
    // named as it appears in the certificate: "用途が違います" would not tell anyone which field
    // to look at, and this is a line somebody has to be able to act on.
    const why = !timestamp.imprintMatches
      ? "この署名を対象としていません"
      : !timestamp.signatureVerified
        ? "トークンの署名が検証できません"
        : !timestamp.timestampingEku
          ? "応答者証明書に timeStamping の拡張鍵用途がありません"
          : (timestamp.chain.reason ?? "ルートに到達しません");
    return {
      tone: "bad",
      label: "タイムスタンプ",
      value: `${formatJst(timestamp.genTime)} — ${why}`,
    };
  }
  const anchor = timestamp.chain.anchor ?? "未検証";
  return {
    tone: "ok",
    label: "タイムスタンプ",
    value: formatJst(timestamp.genTime),
    // Who signed the token and what it chains to. It is long — a responder DN and a root name on
    // one line — and it qualifies nothing: the claim is the time, and the tick already says the
    // chain was checked. Folded, so that the moment being asserted is what the eye lands on.
    detail: timestamp.tsaName
      ? `応答者: ${timestamp.tsaName} / ルート: ${anchor}`
      : `ルート: ${anchor}`,
    detailSummary: "応答者とルート",
  };
}

/**
 * The certificate's standing: the chain, the date it was judged on, and revocation.
 *
 * 失効確認 is in every branch, including the ones where the chain never got anywhere. It is the
 * claim this program cannot make, and leaving it out where other things already failed would let
 * a reader believe it was made somewhere.
 */
export function trustClaims(trust: TrustCheck | null): ClaimLine[] {
  // Unconditional: `revocationChecked` is false in every build of this program, and a line that
  // appears only sometimes is a line whose absence reads as "checked, fine".
  const revocation: ClaimLine = {
    tone: "unknown",
    label: "失効確認",
    value: "未実施（本アプリは JPKI 失効情報サービスを参照しません）",
    detail: "証明書が失効していても、この結果は変わりません。",
  };
  if (!trust) {
    return [
      { tone: "unknown", label: "証明書チェーン", value: "証明書がないため未検証" },
      revocation,
    ];
  }
  if (trust.result === "failed") {
    return [
      { tone: "bad", label: "証明書チェーン", value: trust.reason },
      revocation,
    ];
  }
  return [
    {
      // A test hierarchy never becomes something confirmed. The chain does reach a root, but the
      // root is not the one that stands behind a person's card, so the claim stays qualified.
      tone: trust.testHierarchy ? "warn" : "ok",
      label: "証明書チェーン",
      value: trust.testHierarchy
        ? "J-LIS ルートまで到達（テスト階層）"
        : "J-LIS ルートまで到達",
      detail: trust.testHierarchy
        ? "テスト階層 — 実在の本人ではありません。"
        : undefined,
    },
    {
      tone: trust.reference.source === "timestamp" ? "ok" : "warn",
      label: "判定基準日",
      value: `${formatJst(trust.reference.at)}（${
        trust.reference.source === "timestamp" ? "タイムスタンプ" : "現在時刻"
      }）`,
      detail:
        trust.reference.source === "timestamp"
          ? undefined
          : "証明書が期限切れになると検証できなくなります。",
    },
    revocation,
  ];
}

/** A time the signer wrote down themselves. Evidence of nothing, and labelled as such. */
function claimedTimeClaim(label: string, at: string | null): ClaimLine {
  return {
    tone: "unknown",
    label,
    value: formatJst(at),
    detail: "署名した側の端末が申告した時刻で、検証されていません。",
  };
}

// --- OpenPGP -------------------------------------------------------------------------------------

/**
 * What the signature itself establishes.
 *
 * A detached OpenPGP signature is checked against the document, so this claim may say so. The PDF
 * one may not — see `pdfSignatureClaim`.
 */
function pgpSignatureClaim(v: PgpVerification): ClaimLine {
  if (!v.signatureVerified) {
    return {
      tone: "bad",
      label: "署名の検証",
      value: "この文書と署名は一致しません",
      detail:
        "原本が署名の後で変わったか、この証明書の鍵で作られた署名ではないかのどちらかです。",
    };
  }
  if (!v.certificate) {
    return {
      tone: "ok",
      label: "署名の検証",
      value: "この文書に対し、署名に含まれる鍵で作られた署名です",
      detail: "証明書が添付されていないため、その鍵が誰のものかは分かりません。",
    };
  }
  if (!v.keyMatchesCertificate) {
    return {
      tone: "bad",
      label: "署名の検証",
      value: "署名を作った鍵が、添付されている証明書の鍵と一致しません",
      detail: "他人の証明書が貼り付けられている可能性があります。",
    };
  }
  return {
    tone: "ok",
    label: "署名の検証",
    value: "この文書に対し、この証明書の鍵で作られた署名です",
  };
}

/** Every claim a PGP verification makes, in display order. */
export function pgpClaims(v: PgpVerification): ClaimLine[] {
  return [
    pgpSignatureClaim(v),
    timestampClaim(v.timestamp),
    ...trustClaims(v.trust),
    claimedTimeClaim("署名時刻（自己申告）", v.claimedCreationTime),
  ];
}

// --- PDF ------------------------------------------------------------------------------------------

/**
 * What the CMS signature establishes, which is less than it looks.
 *
 * The signature covers `signedAttrs`, not the document: the document is reached through the
 * `messageDigest` attribute, and that is the next claim down. So this one says "この証明書の鍵で
 * 作られた署名です" and stops there. Writing "この文書に対し" here would fold two independent
 * checks into one sentence, and a genuine signature over a document that was later altered — the
 * case the pair exists to catch — would read as if it were fine.
 */
function pdfSignatureClaim(v: PdfSignatureVerification): ClaimLine {
  if (!v.signatureVerified) {
    return {
      tone: "bad",
      label: "署名の検証",
      value: "この証明書の鍵で作られた署名として検証できません",
    };
  }
  if (!v.certificate) {
    return {
      tone: "unknown",
      label: "署名の検証",
      value: "署名者の証明書を取り出せませんでした",
    };
  }
  if (!v.signingCertificateBound) {
    return {
      // Not "問題あり": the attribute may simply be absent, or use a hash this program does not
      // compute. What can be said is that the tie was not confirmed, not that it is wrong.
      tone: "warn",
      label: "署名の検証",
      value:
        "この証明書の鍵で作られた署名ですが、証明書を指定する情報（signingCertificate 属性）を確認できません",
      detail:
        "署名が本当にこの証明書に向けて作られたのかを、署名の中の情報で裏づけられません。",
    };
  }
  return {
    tone: "ok",
    label: "署名の検証",
    value: "この証明書の鍵で作られた署名です",
    detail: "文書が署名時のままかどうかは「文書の同一性」が示します。",
  };
}

/** Every claim one PDF signature makes, in display order. */
export function pdfClaims(v: PdfSignatureVerification): ClaimLine[] {
  const claims: ClaimLine[] = [
    pdfSignatureClaim(v),
    {
      tone: v.documentDigestMatches ? "ok" : "bad",
      label: "文書の同一性",
      value: v.documentDigestMatches
        ? "署名時から変更されていません"
        : "署名対象と一致しません",
      detail: v.documentDigestMatches
        ? undefined
        : "この署名が対象とした内容と、いま開いているファイルが違います。",
    },
    {
      tone: v.byteRangeSound ? "ok" : "bad",
      label: "署名範囲",
      value: v.byteRangeSound
        ? "署名欄以外のすべてを署名しています"
        : "署名されていない領域があります（内容が隠されている可能性）",
    },
    {
      // Appending is how a second signature is added, so this is a warning and not a failure.
      tone: v.coversWholeFile ? "ok" : "warn",
      label: "署名後の追記",
      value: v.coversWholeFile
        ? "なし"
        : `この署名の後に ${v.bytesAfter} バイトが追記されています`,
      detail: v.coversWholeFile
        ? undefined
        : "後から署名が足された場合もこうなります。追記の中身はこの署名の対象ではありません。",
    },
    timestampClaim(v.timestamp),
    ...trustClaims(v.trust),
    claimedTimeClaim("署名時刻（自己申告）", v.claimedSigningTime),
  ];
  if (v.claimedName) {
    claims.push({
      tone: "unknown",
      label: "署名欄の名前（自己申告）",
      value: v.claimedName,
      detail: "署名者が書き込んだ文字列で、証明書とは照合していません。",
    });
  }
  if (v.reason) {
    claims.push({ tone: "unknown", label: "理由（自己申告）", value: v.reason });
  }
  if (v.location) {
    claims.push({ tone: "unknown", label: "場所（自己申告）", value: v.location });
  }
  return claims;
}

// --- The text file --------------------------------------------------------------------------------

/**
 * The signer, as the report may describe them.
 *
 * `bound` is the same condition the screen uses to decide whether to show a name: whether this
 * certificate is tied to this signature. Withholding it is not about how good the signature is —
 * a tampered PDF can carry a signature that verifies perfectly well under its signer's
 * certificate, and that signer's name belongs on the report.
 */
export interface ReportSigner {
  certificate: CertificateInfo | null;
  bound: boolean;
  /** Why the name is withheld, when it is. A default is used when this is not given. */
  unboundReason?: string | null;
}

export interface ReportOptions {
  /** Which signature this is, for a document carrying more than one. */
  heading?: string;
  /**
   * Write 住所・生年月日・性別 out as well.
   *
   * Off unless the person exporting asks for it. A verification result is something people paste
   * into mail and attach to tickets, and the certificate holds a home address.
   */
  includePersonalDetails?: boolean;
}

/**
 * The lines `export_verification` is given — the same sentences as the screen.
 *
 * No title and no disclaimer: both are added on the Rust side, where a caller cannot forget them.
 */
export function reportLines(
  claims: ClaimLine[],
  signer?: ReportSigner | null,
  options?: ReportOptions,
): string[] {
  const lines: string[] = [];
  if (options?.heading) lines.push(options.heading);
  for (const claim of claims) lines.push(...claimText(claim));
  lines.push(
    ...signerLines(signer ?? null, options?.includePersonalDetails === true),
  );
  return lines;
}

function claimText(claim: ClaimLine): string[] {
  const lines = [`[${TONE_WORDS[claim.tone]}] ${claim.label}: ${claim.value}`];
  if (claim.detail) lines.push(`    ${claim.detail}`);
  return lines;
}

function signerLines(
  signer: ReportSigner | null,
  includePersonalDetails: boolean,
): string[] {
  if (!signer) return [];
  const certificate = signer.certificate;
  if (!certificate) {
    return claimText({
      tone: "unknown",
      label: "署名者",
      value: "証明書が添付されていないため分かりません",
    });
  }
  const fingerprint = `フィンガープリント: ${certificate.fingerprint}`;
  if (!signer.bound) {
    // The fingerprint identifies the certificate without naming anybody, and the reader needs
    // something to go on when the name is the part being withheld.
    return [
      ...claimText({
        tone: "bad",
        label: "署名者",
        value:
          signer.unboundReason ??
          "この署名と証明書の結び付きが確認できないため、氏名は出力しません",
      }),
      fingerprint,
    ];
  }

  const holder = certificate.holder;
  const notes = [describeSubstitutes("氏名", holder.nameSubstitutes)];
  // The address's substituted characters are only mentioned where the address itself is, since a
  // warning about the third character of a field that is not in the file has nothing to attach to.
  if (includePersonalDetails) {
    notes.push(describeSubstitutes("住所", holder.addressSubstitutes));
  }
  const substitutions = notes.filter((note): note is string => note !== null);

  const lines = claimText({
    tone: substitutions.length > 0 ? "warn" : "ok",
    label: "署名者",
    value: holder.name ?? certificate.commonName ?? certificate.subject,
  });
  for (const note of substitutions) lines.push(`    ${note}`);

  const personal: [string, string | null][] = [
    ["住所", holder.address],
    ["生年月日", holder.birthDate],
    ["性別", describeSex(holder.sex)],
  ];
  const present = personal.filter(
    (entry): entry is [string, string] => entry[1] !== null && entry[1] !== "",
  );
  if (includePersonalDetails) {
    for (const [label, value] of present) lines.push(`${label}: ${value}`);
    // Fields whose shape was not recognised, shown by OID. Held to the same rule as the four:
    // nobody knows what is in them, which is a reason to disclose them less readily, not more.
    for (const [oid, value] of holder.other) lines.push(`${oid}: ${value}`);
  } else {
    if (present.length > 0) {
      lines.push("住所・生年月日・性別: 出力時に省略（証明書には含まれています）");
    }
    // Said separately, and only when there are any: rolling them into the line above would name
    // three fields that this certificate may not even carry.
    if (holder.other.length > 0) {
      lines.push(
        "その他の記載事項（OID 表示）: 出力時に省略（証明書には含まれています）",
      );
    }
  }

  lines.push(`発行者: ${certificate.issuer}`);
  lines.push(`証明書の有効期間: ${certificate.notBefore} 〜 ${certificate.notAfter}`);
  lines.push(fingerprint);
  return lines;
}
