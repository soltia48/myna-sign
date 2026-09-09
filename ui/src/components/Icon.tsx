import type { Screen } from "../lib/state";

/** Decorative navigation cues; the adjacent text supplies the accessible name. */
export function Icon({ name }: { name: Screen | "arrow" | "file" }) {
  return (
    <svg
      class="icon"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      stroke-width="1.5"
      stroke-linecap="round"
      stroke-linejoin="round"
      aria-hidden="true"
      focusable="false"
    >
      {name === "card" && (
        <>
          <rect x="3" y="5" width="18" height="14" rx="2" />
          <rect x="6" y="9" width="4" height="5" rx="1" />
          <path d="M14 10h4m-4 4h4" />
        </>
      )}
      {name === "sign" && <path d="m15 4 5 5M4 20l5-1L20 8a2.1 2.1 0 0 0-5-5L4 14zM4 20h16" />}
      {name === "verify" && <path d="M12 3 4 6v6c0 5 8 9 8 9s8-4 8-9V6zM8 12l3 3 5-6" />}
      {name === "settings" && (
        <>
          <path d="M4 7h2m6 0h8M4 17h8m6 0h2" />
          <circle cx="9" cy="7" r="3" />
          <circle cx="15" cy="17" r="3" />
        </>
      )}
      {name === "arrow" && <path d="M5 12h14m-5-5 5 5-5 5" />}
      {name === "file" && <path d="M14 3H6a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9zM14 3v6h6M8 13h8m-8 4h5" />}
    </svg>
  );
}
