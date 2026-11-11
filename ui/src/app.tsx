import { useEffect, useRef, useState } from "preact/hooks";

import { banner, cardStatus, screen, signBusy, signProgress, type Screen } from "./lib/state";
import { PIN_BLOCKED } from "./lib/api";
import {
  CardScreen,
  SettingsScreen,
  SignScreen,
  VerifyScreen,
  retriesTone,
} from "./components/screens";
import { Icon } from "./components/Icon";

const TABS: [Screen, string][] = [
  ["card", "カード"],
  ["sign", "署名"],
  ["verify", "検証"],
  ["settings", "設定"],
];

/**
 * Read as `Record<string, string>` rather than as the `Progress["stage"]` union: the set of
 * stages is decided in Rust, and an unknown one should degrade to a vague word instead of
 * failing to build here.
 */
const STAGES: Record<string, string> = {
  signing: "署名中",
  timestamping: "タイムスタンプ取得中",
  writing: "書き出し中",
};

const basename = (path: string) => path.split(/[\\/]/).pop() ?? path;

function screenFor(id: Screen) {
  switch (id) {
    case "card":
      return <CardScreen />;
    case "sign":
      return <SignScreen />;
    case "verify":
      return <VerifyScreen />;
    case "settings":
      return <SettingsScreen />;
  }
}

/**
 * The card, as it stands, on every screen.
 *
 * Signing spends an attempt of a password that locks at a town hall counter, and the card screen is
 * the only place that said how many were left — two tabs away from the button that spends one. The
 * count is drawn here as the largest thing in the rail for that reason. No maximum and no row of
 * pips: the card reports what is left and nothing else (see `retriesConsequence`).
 *
 * Not a live region: the card screen and the banner already announce every change, and a second
 * voice saying the same number would be noise.
 */
function CardSummary() {
  const status = cardStatus.value;
  const retries = status?.signPinRetries ?? null;
  const tone = status ? retriesTone(retries) : "unknown";
  return (
    <section class="rail-card" data-tone={tone} aria-labelledby="rail-card-title">
      <div class="rail-card-head">
        <span class="rail-card-chip" aria-hidden="true" />
        <h2 id="rail-card-title" class="rail-card-state">
          {status ? "カード接続中" : "カード未接続"}
        </h2>
      </div>
      {status ? (
        status.hasSignCertificate ? (
          <p class="rail-card-count">
            <span class="rail-card-label">署名用パスワード</span>
            {retries === null ? (
              <span class="rail-card-value">残り回数不明</span>
            ) : retries === 0 ? (
              <span class="rail-card-value">{PIN_BLOCKED.claim}</span>
            ) : (
              <span class="rail-card-value">
                残り <strong>{retries}</strong> 回
              </span>
            )}
          </p>
        ) : (
          <p class="rail-card-count">
            <span class="rail-card-label">署名用電子証明書なし</span>
          </p>
        )
      ) : (
        <p class="rail-card-count">
          <span class="rail-card-label">「カード」で接続します</span>
        </p>
      )}
    </section>
  );
}

export function App() {
  const current = screen.value;
  const message = banner.value;
  const progress = signProgress.value;

  const selected = TABS.findIndex(([id]) => id === current);
  const tabs = useRef<(HTMLButtonElement | null)[]>([]);

  /**
   * Which tab holds the keyboard, which is not always the selected one: the arrow keys move
   * focus without selecting, so that reaching a tab and choosing it stay separate acts.
   */
  const [focused, setFocused] = useState(selected);
  useEffect(() => {
    setFocused(selected);
  }, [selected]);

  /**
   * A message belongs to the screen it was raised on. Clearing happens here, on the change of
   * screen itself, so that it also covers a screen change made from inside a screen — but only
   * for a message that was already showing when the change happened. A component that navigates
   * and then explains why must not be silenced by its own navigation, so the sequence number
   * decides: a message the previous screen never saw is a new one.
   */
  const showing = useRef<number | null>(null);
  useEffect(() => {
    const shown = banner.peek();
    if (shown && shown.seq === showing.current) banner.value = null;
  }, [current]);
  useEffect(() => {
    showing.current = message?.seq ?? null;
  }, [message?.seq]);

  /**
   * Manual activation. Selecting on arrow would unmount the signing screen on the first
   * keypress and take everything half-entered there with it; the screens are rendered
   * conditionally, and a card that is already working would go on working unwatched.
   */
  function move(event: KeyboardEvent, index: number) {
    const last = TABS.length - 1;
    let next: number;
    switch (event.key) {
      case "ArrowRight":
      case "ArrowDown":
        next = index === last ? 0 : index + 1;
        break;
      case "ArrowLeft":
      case "ArrowUp":
        next = index === 0 ? last : index - 1;
        break;
      case "Home":
        next = 0;
        break;
      case "End":
        next = last;
        break;
      default:
        return;
    }
    event.preventDefault();
    setFocused(next);
    tabs.current[next]?.focus();
  }

  // Enter and Space arrive as a click on a <button>, so selection needs no key handling of its own.
  function select(id: Screen) {
    screen.value = id;
  }

  const dismiss = (
    <button class="ghost small" aria-label="この通知を閉じる" onClick={() => (banner.value = null)}>
      閉じる
    </button>
  );

  /**
   * `seq` as the key, so that the same sentence said twice is torn down and rebuilt rather than
   * left untouched: an unchanged live region announces nothing, and a repeated failure is exactly
   * the case where the user needs to hear it again.
   */
  const shown = message && (
    <div key={message.seq} class={`banner banner-${message.tone}`}>
      <span>{message.text}</span>
      {dismiss}
    </div>
  );

  return (
    <div class="app">
      <a class="skip-link" href="#main-content">本文へ移動</a>
      {/* The rail is the window's spine: where you are, and what the card can still do. It stays
          put while the work beside it scrolls. Vertical arrows move between tabs as well as
          horizontal ones, since the strip turns into a row on a narrow window. */}
      <aside class="rail">
        <div class="identity">
          <span class="identity-mark"><Icon name="sign" /></span>
          <span>Myna Sign</span>
        </div>
        <nav class="tabs" role="tablist" aria-label="画面" aria-orientation="vertical">
          {TABS.map(([id, label], index) => (
            <button
              key={id}
              id={`tab-${id}`}
              ref={(element) => {
                tabs.current[index] = element;
              }}
              class="tab"
              role="tab"
              type="button"
              aria-selected={current === id}
              aria-controls={`panel-${id}`}
              tabIndex={focused === index ? 0 : -1}
              onClick={() => select(id)}
              onKeyDown={(event) => move(event, index)}
            >
              <Icon name={id} />
              <span class="tab-label">{label}</span>
              {id === "sign" && signBusy.value && <span class="tab-busy">実行中</span>}
            </button>
          ))}
        </nav>
        <CardSummary />
      </aside>

      <div class="workspace">
        {/* The message sticks to the top of the work it is about. Both regions stand whether or not
            there is anything to say: a live region added to the page at the same moment as its text
            is often read as ordinary content and announced by nothing. Errors are the only tone
            worth interrupting for. */}
        <div class="messages">
          <div role="status" aria-live="polite">
            {message && message.tone !== "error" && shown}
          </div>
          <div role="alert" aria-live="assertive">
            {message && message.tone === "error" && shown}
          </div>

          {/* Progress is spoken here and drawn by the signing screen, so that it keeps being spoken
              after the user has left that screen. `aria-atomic` because the parts of this sentence
              change independently: without it a screen reader says "4" and nothing else. */}
          <div class="visually-hidden" role="status" aria-live="polite" aria-atomic="true">
            {progress && progress.stage !== "done" && (
              <span key={`${progress.index}-${progress.stage}`}>
                {STAGES[progress.stage] ?? "処理中"} {progress.index + 1}/{progress.total}
                {progress.path && ` ${basename(progress.path)}`}
              </span>
            )}
          </div>
        </div>

        {/* The panels live inside <main> rather than being it: a `role` on <main> would replace the
            landmark, and the one landmark this window has is worth more than a tidier tree. */}
        <main id="main-content" tabIndex={-1}>
          {TABS.map(([id]) => (
            <div
              key={id}
              id={`panel-${id}`}
              role="tabpanel"
              aria-labelledby={`tab-${id}`}
              hidden={current !== id}
            >
              {current === id && screenFor(id)}
            </div>
          ))}
        </main>
      </div>
    </div>
  );
}
