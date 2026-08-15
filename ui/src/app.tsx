import { useEffect, useRef, useState } from "preact/hooks";

import { banner, screen, signBusy, signProgress, type Screen } from "./lib/state";
import { CardScreen, SettingsScreen, SignScreen, VerifyScreen } from "./components/screens";

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
        next = index === last ? 0 : index + 1;
        break;
      case "ArrowLeft":
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
      {/* Tabs and message in one sticky wrapper: the message is about what the buttons above it
          just did, and it is worth nothing once it has scrolled away. Sticking the wrapper rather
          than its parts keeps the offset out of the stylesheet — the strip is as tall as the font
          makes it. */}
      <div class="topbar">
        <nav class="tabs" role="tablist" aria-label="画面">
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
              {label}
              {id === "sign" && signBusy.value && <span class="tab-busy">実行中</span>}
            </button>
          ))}
        </nav>

        {/* Both regions stand whether or not there is anything to say. A live region added to the
            page at the same moment as its text is often read as ordinary content and announced by
            nothing. Errors are the only tone worth interrupting for. */}
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
      <main>
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
  );
}
