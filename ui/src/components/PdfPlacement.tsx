/**
 * Placing the signature on the page by dragging it there, or with the keyboard.
 *
 * The document scrolls continuously: every page is stacked in one scrolling area, and a drag on
 * any of them places the signature on that page. There is no "current page" to set first.
 *
 * # Two coordinate systems
 *
 * The canvas counts pixels from the top left. PDF user space counts points from the bottom left,
 * and a page does not have to start at the origin — `/MediaBox` can put it anywhere, and different
 * pages of one document can differ. Converting by hand means getting the flip, the scale and the
 * origin right for every page; pdf.js already knows all three, so every conversion goes through
 * the `viewport` of the page it belongs to.
 *
 * **One CSS pixel of a canvas is one unit of that page's viewport.** Each canvas is given an
 * explicit CSS size and the surrounding element scrolls; a canvas is never allowed to shrink to
 * fit, because a canvas displayed smaller than it was rendered would make every conversion
 * silently wrong — the signature would land somewhere other than where it was drawn. Zooming
 * re-renders at a new scale rather than stretching what is there.
 *
 * The same promise is why the cached viewports are thrown away whenever the scale changes: a
 * viewport kept from the previous scale would convert against a canvas that no longer exists at
 * that size, which is the same silent error by another route.
 *
 * The keyboard does its arithmetic in points and never in pixels, so that a nudge means the same
 * thing on the page whatever the view happens to be magnified to.
 *
 * # Only what is on screen is drawn
 *
 * A page's slot is laid out at its true size as soon as the document loads, so the scrollbar is
 * right immediately, but the canvas behind it is only painted while the page is near the viewport
 * and is released again once it is not. A three hundred page document would otherwise hold a few
 * gigabytes of bitmaps for the sake of two of them.
 *
 * # The preview is not the signature
 *
 * What is drawn here is the rectangle and a preview of the stamp. The appearance stream that ends
 * up in the file is built in Rust from the same rectangle, so what the user sees is where it lands
 * — but this component never produces any part of the signed document.
 */
import { useCallback, useEffect, useId, useLayoutEffect, useRef, useState } from "preact/hooks";

import { api } from "../lib/api";
import { notify } from "../lib/state";

/** `[x1, y1, x2, y2]` in PDF user space. */
export type Rect = [number, number, number, number];

interface Props {
  /** The PDF being signed. */
  path: string;
  /** The signer's own stamp image, or nothing for the drawn panel. */
  imagePath: string | null;
  /** What the panel would say, when there is no image of the signer's own. */
  panel: { reason: string | null; location: string | null } | null;
  page: number;
  rect: Rect | null;
  /// Whether `rect` is the default rather than somewhere the signer chose.
  ///
  /// Shown dashed and labelled, so that "where it will land" and "where I put it" do not look the
  /// same — the first is a suggestion the signer may not have noticed.
  provisional: boolean;
  onChange: (page: number, rect: Rect) => void;
}

/** The width a page is drawn at when nothing can be measured yet, in CSS pixels. */
const FALLBACK_WIDTH = 520;
const ZOOM_STEPS = [0.5, 0.75, 1, 1.5, 2, 3];
/**
 * How tall the scrolling area is allowed to get. Held as numbers as well as as CSS because the
 * fit has to be worked out before there is any laid-out page to measure: the element is only as
 * tall as its contents until it reaches this cap, so measuring it while it is empty would answer
 * with the empty state and every page would come out too small.
 */
const VIEWPORT_VH = 72;
const VIEWPORT_MAX_HEIGHT = 820;
const VIEWPORT_HEIGHT = `min(${VIEWPORT_VH}vh, ${VIEWPORT_MAX_HEIGHT}px)`;
/** Room left for the scrollbar, which appears as soon as there is more than one page. */
const SCROLLBAR_SLACK = 18;
/** How far outside the visible area a page is still painted. */
const RENDER_MARGIN = "300px";
/** How close to the edge a drag has to get before the view follows it, and how fast it moves. */
const AUTOSCROLL_MARGIN = 28;
const AUTOSCROLL_SPEED = 12;
/** How far one press of an arrow key moves or resizes the rectangle, in PDF points. */
const STEP = 4;
const BIG_STEP = 20;
/** The smallest side the keyboard will leave, in points. A flatter rectangle holds no stamp. */
const MIN_SIDE = 12;
/**
 * Roughly how large the "既定の位置" label is, in CSS pixels. Its own position has to be worked out
 * here rather than left to CSS: the label does not wrap, and one hanging off the side of a page
 * would scroll the whole view sideways. Deliberately generous — overestimating only tucks the
 * label a little further in than it needed to go.
 */
const TAG_WIDTH = 96;
const TAG_HEIGHT = 20;

/** Which way a key points on screen, where y grows downwards. */
const ARROWS: Record<string, [number, number]> = {
  ArrowLeft: [-1, 0],
  ArrowRight: [1, 0],
  ArrowUp: [0, -1],
  ArrowDown: [0, 1],
};

interface Viewport {
  width: number;
  height: number;
  convertToPdfPoint: (x: number, y: number) => number[];
  convertToViewportPoint: (x: number, y: number) => number[];
}

interface Box {
  x: number;
  y: number;
  w: number;
  h: number;
}

/** A page's size in PDF points. What it is drawn at is derived, never stored. */
interface PageSize {
  width: number;
  height: number;
  /** The page's own box, since a page does not have to begin at the origin. */
  bounds: Rect;
}

export function PdfPlacement({
  path,
  imagePath,
  panel,
  page,
  rect,
  provisional,
  onChange,
}: Props) {
  const scroller = useRef<HTMLDivElement>(null);
  const slotElements = useRef(new Map<number, HTMLDivElement>());
  const canvases = useRef(new Map<number, HTMLCanvasElement>());
  const viewports = useRef(new Map<number, Viewport>());
  const painted = useRef(new Set<number>());
  const tasks = useRef(new Map<number, { cancel: () => void }>());
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const document = useRef<any>(null);
  const dragging = useRef<{ page: number; x: number; y: number } | null>(null);
  const autoscroll = useRef<number | null>(null);
  /**
   * The scale everything on screen is meant to be at. A paint that started before the scale moved
   * on and finishes after it has to be dropped rather than allowed to finish: it would leave a
   * canvas and a cached viewport that disagree about how big the page is, and every conversion
   * through that pair would be quietly wrong.
   */
  const drawnAt = useRef(1);
  const helpId = useId();

  const [sizes, setSizes] = useState<PageSize[]>([]);
  const [zoom, setZoom] = useState(1);
  const [scale, setScale] = useState(1);
  const [visible, setVisible] = useState<Set<number>>(new Set());
  const [current, setCurrent] = useState(1);
  const [tabStop, setTabStop] = useState(1);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [imageUrl, setImageUrl] = useState<string | null>(null);
  const [live, setLive] = useState<{ page: number; box: Box } | null>(null);

  // Whatever will actually be drawn: the signer's image, or the panel this program generates.
  useEffect(() => {
    let created: string | null = null;
    const wanted = imagePath
      ? api.readFile(imagePath)
      : panel
        ? api.previewSignaturePanel(panel.reason, panel.location)
        : null;
    if (!wanted) {
      setImageUrl(null);
      return;
    }
    wanted
      .then((bytes) => {
        created = URL.createObjectURL(new Blob([bytes]));
        setImageUrl(created);
      })
      .catch(() => setImageUrl(null));
    return () => {
      if (created) URL.revokeObjectURL(created);
    };
  }, [imagePath, panel?.reason, panel?.location]);

  // Load the document and work out how tall the whole thing is.
  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);
    setSizes([]);
    painted.current.clear();
    viewports.current.clear();

    (async () => {
      // Loaded on demand: pdf.js is by far the largest thing in the bundle, and a window that
      // never signs a PDF should never pay for it.
      const pdfjs = await import("pdfjs-dist");
      pdfjs.GlobalWorkerOptions.workerSrc = new URL(
        "pdfjs-dist/build/pdf.worker.mjs",
        import.meta.url,
      ).href;

      const bytes = await api.readFile(path);
      const loaded = await pdfjs.getDocument({ data: new Uint8Array(bytes) }).promise;
      if (cancelled) return;
      document.current = loaded;

      // Every page shares one scale, so a landscape page among portrait ones looks wider rather
      // than being squashed to the same width.
      const found: PageSize[] = [];
      for (let n = 1; n <= loaded.numPages; n++) {
        const view = (await loaded.getPage(n)).getViewport({ scale: 1 });
        found.push({
          width: view.width,
          height: view.height,
          bounds: [...view.viewBox] as Rect,
        });
      }
      if (cancelled) return;

      setSizes(found);
      setLoading(false);
    })().catch((e) => {
      if (!cancelled) {
        setError(String(e));
        setLoading(false);
      }
    });

    return () => {
      cancelled = true;
    };
  }, [path]);

  // A whole page has to fit, not just its width: a preview that shows the top two thirds of a
  // sheet hides the corner the signature usually goes in. The window is what decides this, so it
  // is asked again when the window changes size and never at any other time — a new scale throws
  // away every bitmap, which is too expensive to do on a whim. Before the browser paints, so that
  // a freshly opened document is never shown for a frame at the wrong size.
  useLayoutEffect(() => {
    if (sizes.length === 0) return;
    const apply = () =>
      setScale((now) => {
        const next = fitScale(sizes, scroller.current);
        return Math.abs(next - now) < 0.005 ? now : next;
      });
    apply();
    window.addEventListener("resize", apply);
    return () => window.removeEventListener("resize", apply);
  }, [sizes]);

  // A new scale means every bitmap is the wrong resolution and every cached viewport describes a
  // canvas that no longer exists — keeping those would put the signature somewhere other than
  // where it was drawn. The *layout* needs nothing done to it: a slot's size is derived from the
  // page's size in points, so it follows the zoom on its own.
  useEffect(() => {
    drawnAt.current = scale * zoom;
    for (const task of tasks.current.values()) task.cancel();
    tasks.current.clear();
    painted.current.clear();
    viewports.current.clear();
    for (const canvas of canvases.current.values()) {
      canvas.width = 0;
      canvas.height = 0;
    }
    // Re-paint whatever is on screen at the new scale.
    setVisible((shown) => new Set(shown));
  }, [zoom, scale]);

  // The tab stop follows the page the signature is on, so tabbing into the document lands on the
  // page the next arrow key would change.
  useEffect(() => {
    setTabStop(page);
  }, [page]);

  /** Paint one page, if it is not painted already. */
  const paint = useCallback(
    async (n: number) => {
      const loaded = document.current;
      const canvas = canvases.current.get(n);
      if (!loaded || !canvas || painted.current.has(n)) return;
      painted.current.add(n);

      const rendered = await loaded.getPage(n);
      // Overtaken by a zoom or a resize while the page was being fetched; the paint that replaces
      // this one is already on its way.
      if (drawnAt.current !== scale * zoom) return;
      const viewport = rendered.getViewport({ scale: scale * zoom });
      viewports.current.set(n, viewport);

      // Draw at the device's pixel density but lay out at the viewport's size, so the page stays
      // sharp while one CSS pixel keeps meaning one viewport unit.
      const density = window.devicePixelRatio || 1;
      canvas.width = Math.floor(viewport.width * density);
      canvas.height = Math.floor(viewport.height * density);
      canvas.style.width = `${viewport.width}px`;
      canvas.style.height = `${viewport.height}px`;

      const context = canvas.getContext("2d");
      if (!context) return;
      const task = rendered.render({
        canvas,
        canvasContext: context,
        viewport,
        transform: density === 1 ? undefined : [density, 0, 0, density, 0, 0],
      });
      tasks.current.set(n, task);
      try {
        await task.promise;
      } catch {
        // Cancelled by a zoom or by scrolling away; it will be painted again if it comes back.
        painted.current.delete(n);
      } finally {
        tasks.current.delete(n);
      }
    },
    [scale, zoom],
  );

  /** Release a page that has scrolled well away. */
  const release = useCallback((n: number) => {
    tasks.current.get(n)?.cancel();
    tasks.current.delete(n);
    painted.current.delete(n);
    const canvas = canvases.current.get(n);
    if (canvas) {
      canvas.width = 0;
      canvas.height = 0;
    }
  }, []);

  // Watch which pages are near the viewport.
  useEffect(() => {
    const root = scroller.current;
    if (!root || sizes.length === 0) return;

    const observer = new IntersectionObserver(
      (entries) => {
        setVisible((previous) => {
          const next = new Set(previous);
          for (const entry of entries) {
            const n = Number((entry.target as HTMLElement).dataset.page);
            if (entry.isIntersecting) next.add(n);
            else next.delete(n);
          }
          return next;
        });
      },
      { root, rootMargin: RENDER_MARGIN },
    );

    for (const element of slotElements.current.values()) observer.observe(element);
    return () => observer.disconnect();
  }, [sizes.length]);

  // Paint what is visible, release what is not.
  useEffect(() => {
    for (const n of visible) void paint(n);
    for (const n of [...painted.current]) {
      if (!visible.has(n)) release(n);
    }
    // The page shown in the readout is the one in the middle of the view.
    const shown = [...visible].sort((a, b) => a - b);
    if (shown.length > 0) setCurrent(shown[Math.floor(shown.length / 2)]);
  }, [visible, paint, release]);

  function positionIn(n: number, event: PointerEvent) {
    const slot = slotElements.current.get(n);
    if (!slot) return { x: 0, y: 0 };
    const bounds = slot.getBoundingClientRect();
    // `getBoundingClientRect` already accounts for how far the container is scrolled, so the
    // arithmetic is the same wherever the page happens to be.
    return {
      x: clamp(event.clientX - bounds.left, 0, bounds.width),
      y: clamp(event.clientY - bounds.top, 0, bounds.height),
    };
  }

  function extendTo(now: { x: number; y: number }) {
    const start = dragging.current;
    if (!start) return;
    setLive({
      page: start.page,
      box: {
        x: Math.min(start.x, now.x),
        y: Math.min(start.y, now.y),
        w: Math.abs(now.x - start.x),
        h: Math.abs(now.y - start.y),
      },
    });
  }

  /** Follow a drag that has reached the edge of the visible area. */
  function follow(event: PointerEvent) {
    const view = scroller.current;
    if (!view) return;
    const bounds = view.getBoundingClientRect();

    let dy = 0;
    if (event.clientY - bounds.top < AUTOSCROLL_MARGIN) dy = -AUTOSCROLL_SPEED;
    else if (bounds.bottom - event.clientY < AUTOSCROLL_MARGIN) dy = AUTOSCROLL_SPEED;

    if (autoscroll.current !== null) {
      cancelAnimationFrame(autoscroll.current);
      autoscroll.current = null;
    }
    if (dy === 0) return;

    // Deliberately not subject to `prefers-reduced-motion`, unlike `jumpTo`: dragging past the
    // edge is the only way to draw a rectangle taller than the visible area, so stilling this
    // would take the ability away rather than calm it down.
    const step = () => {
      view.scrollBy(0, dy);
      // The pointer has not moved, but the page under it has, so the rectangle has to keep up.
      const start = dragging.current;
      if (start) extendTo(positionIn(start.page, event));
      autoscroll.current = requestAnimationFrame(step);
    };
    autoscroll.current = requestAnimationFrame(step);
  }

  function down(n: number, event: PointerEvent) {
    if (loading || error) return;
    (event.currentTarget as HTMLElement).setPointerCapture(event.pointerId);
    const start = positionIn(n, event);
    dragging.current = { page: n, ...start };
    setLive({ page: n, box: { x: start.x, y: start.y, w: 0, h: 0 } });
  }

  function move(event: PointerEvent) {
    const start = dragging.current;
    if (!start) return;
    // A drag that wanders onto another page still belongs to the page it started on: a signature
    // field cannot span two.
    extendTo(positionIn(start.page, event));
    follow(event);
  }

  function up() {
    if (autoscroll.current !== null) {
      cancelAnimationFrame(autoscroll.current);
      autoscroll.current = null;
    }
    const start = dragging.current;
    dragging.current = null;
    const drawn = live;
    setLive(null);
    if (!start || !drawn) return;

    const viewport = viewports.current.get(start.page);
    // A stray click is not a rectangle. Leaving it would produce a zero-area field, which the Rust
    // side refuses anyway — better to say nothing happened.
    if (!viewport || drawn.box.w < 8 || drawn.box.h < 8) return;
    onChange(start.page, toPdf(viewport, drawn.box));
  }

  function jumpTo(wanted: number) {
    const slot = slotElements.current.get(clamp(wanted, 1, sizes.length));
    const still = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    slot?.scrollIntoView({ block: "start", behavior: still ? "auto" : "smooth" });
  }

  function moveFocus(wanted: number) {
    const n = clamp(wanted, 1, sizes.length);
    setTabStop(n);
    // Scrolled by `jumpTo` instead, so that one setting decides how the view moves.
    slotElements.current.get(n)?.focus({ preventScroll: true });
    jumpTo(n);
  }

  /**
   * Put the signature on page `n` without the signer having to draw anything.
   *
   * A rectangle that already exists keeps its size and only changes page. When there is none, the
   * default comes from the Rust side, which is where the rule lives; a second rule here would
   * drift from the one that ends up in the file.
   */
  async function placeOn(n: number) {
    const size = sizes[n - 1];
    if (!size) return;
    if (rect) {
      onChange(n, fitInto(rect, size.bounds));
      return;
    }
    try {
      const placement = await api.defaultSignaturePlacement(
        path,
        imagePath,
        panel?.reason ?? null,
        panel?.location ?? null,
      );
      onChange(n, fitInto(placement.rect, size.bounds));
    } catch {
      notify("error", "既定の署名位置を取得できませんでした。ドラッグで指定してください。");
    }
  }

  /** Back to wherever the signing path would put it on its own. */
  async function resetToDefault() {
    try {
      const placement = await api.defaultSignaturePlacement(
        path,
        imagePath,
        panel?.reason ?? null,
        panel?.location ?? null,
      );
      onChange(placement.page, placement.rect);
      moveFocus(placement.page);
    } catch {
      notify("error", "既定の署名位置を取得できませんでした。ドラッグで指定してください。");
    }
  }

  function stepZoom(direction: 1 | -1) {
    const index = ZOOM_STEPS.indexOf(zoom);
    if (index >= 0) {
      setZoom(ZOOM_STEPS[clamp(index + direction, 0, ZOOM_STEPS.length - 1)]);
      return;
    }
    // The zoom is between two steps. It has to move from where it actually is: starting from a
    // fixed point in the list instead would send every press but the first back to the same place.
    const next =
      direction > 0
        ? ZOOM_STEPS.find((step) => step > zoom)
        : [...ZOOM_STEPS].reverse().find((step) => step < zoom);
    setZoom(next ?? ZOOM_STEPS[direction > 0 ? ZOOM_STEPS.length - 1 : 0]);
  }

  /**
   * The keyboard equivalent of a drag.
   *
   * Everything is worked out in PDF points and clamped to the page's own box, never in canvas
   * pixels: a nudge has to mean the same distance on the paper whether the view is at 50% or 300%.
   * Which way "left" runs in those points is asked of the viewport, because a rotated page does
   * not agree with the obvious answer.
   */
  function key(n: number, event: KeyboardEvent) {
    if (loading || error) return;

    if (event.key === "PageDown" || event.key === "PageUp") {
      event.preventDefault();
      moveFocus(n + (event.key === "PageDown" ? 1 : -1));
      return;
    }
    if (event.key === "Home" || event.key === "End") {
      event.preventDefault();
      moveFocus(event.key === "Home" ? 1 : sizes.length);
      return;
    }
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      void placeOn(n);
      return;
    }

    const direction = ARROWS[event.key];
    // Without a rectangle on this page there is nothing to nudge, so the arrows are left to scroll.
    if (!direction || !rect || page !== n) return;
    const bounds = sizes[n - 1]?.bounds;
    if (!bounds) return;
    event.preventDefault();

    const viewport = viewports.current.get(n);
    const step = event.shiftKey ? BIG_STEP : STEP;
    if (event.altKey) {
      // Right and down grow, left and up shrink, with the corner nearest the top left of the
      // screen staying put — the same thing dragging a handle would do.
      const along = direction[0] !== 0 ? [1, 0] : [0, 1];
      const axis = pdfAxis(viewport, along[0], along[1]);
      onChange(n, resize(rect, axis, (direction[0] + direction[1]) * step, bounds));
    } else {
      const axis = pdfAxis(viewport, direction[0], direction[1]);
      onChange(n, fitInto(shift(rect, axis, step), bounds));
    }
  }

  /** The rectangle to draw on page `n`: the one being dragged, or the one already chosen. */
  function boxFor(n: number): Box | null {
    if (live && live.page === n) return live.box;
    if (rect && page === n) {
      const viewport = viewports.current.get(n);
      if (viewport) return toCanvas(viewport, rect);
    }
    return null;
  }

  return (
    <div class="placement">
      <div class="row placement-controls">
        <label class="field page-jump">
          <span>ページ</span>
          <input
            type="number"
            min={1}
            max={Math.max(sizes.length, 1)}
            value={current}
            // On change rather than on input: a page number is not finished until the signer says
            // it is, and jumping at "1" on the way to "12" moves the view and then rewrites what
            // was typed.
            onChange={(e) => jumpTo(Number((e.target as HTMLInputElement).value))}
            onKeyDown={(e) => {
              if (e.key !== "Enter") return;
              e.preventDefault();
              jumpTo(Number((e.target as HTMLInputElement).value));
            }}
          />
        </label>
        <span class="page-of">/ {sizes.length || "—"}</span>

        <button
          type="button"
          class="ghost small"
          onClick={() => void resetToDefault()}
          disabled={loading || !!error}
        >
          既定の位置に戻す
        </button>

        <span class="spacer" />

        <button
          type="button"
          class="ghost small"
          aria-label="縮小"
          onClick={() => stepZoom(-1)}
          disabled={zoom <= ZOOM_STEPS[0]}
        >
          −
        </button>
        <span class="zoom-of">{Math.round(zoom * 100)}%</span>
        <button
          type="button"
          class="ghost small"
          aria-label="拡大"
          onClick={() => stepZoom(1)}
          disabled={zoom >= ZOOM_STEPS[ZOOM_STEPS.length - 1]}
        >
          +
        </button>
        <button type="button" class="ghost small" onClick={() => setZoom(1)}>
          ページ全体に合わせる
        </button>
      </div>

      {error && <p class="error">プレビューを表示できません: {error}</p>}

      <div class="page-viewport" ref={scroller} style={{ maxHeight: VIEWPORT_HEIGHT }}>
        {loading && <p class="page-loading-inline">読み込み中…</p>}
        {sizes.map((size, index) => {
          const number = index + 1;
          const box = boxFor(number);
          const drawing = live !== null && live.page === number;
          const width = size.width * scale * zoom;
          return (
            <div
              key={number}
              class={page === number && rect && !provisional ? "page-slot chosen" : "page-slot"}
              data-page={number}
              // The arrow keys belong to the rectangle here, not to the reading cursor, and a
              // screen reader has to be told that before it will hand them over.
              role="application"
              aria-label={`${number} ページ目`}
              aria-describedby={helpId}
              tabIndex={number === tabStop ? 0 : -1}
              style={{
                width: `${width}px`,
                height: `${size.height * scale * zoom}px`,
              }}
              ref={(element) => {
                if (element) slotElements.current.set(number, element);
                else slotElements.current.delete(number);
              }}
              onFocus={() => setTabStop(number)}
              onKeyDown={(e) => key(number, e)}
              onPointerDown={(e) => down(number, e)}
              onPointerMove={move}
              onPointerUp={up}
              onPointerCancel={up}
            >
              <canvas
                class="page-canvas"
                role="img"
                aria-label={`${number} ページ目のプレビュー。内容は読み上げられません。`}
                ref={(element) => {
                  if (element) canvases.current.set(number, element);
                  else canvases.current.delete(number);
                }}
              />
              <span class="page-number" aria-hidden="true">
                {number}
              </span>
              {box && box.w > 0 && box.h > 0 && (
                <div
                  class={provisional && !drawing ? "page-box provisional" : "page-box"}
                  style={{
                    left: `${box.x}px`,
                    top: `${box.y}px`,
                    width: `${box.w}px`,
                    height: `${box.h}px`,
                  }}
                >
                  {provisional && !drawing && (
                    <span class="page-box-tag" style={tagStyle(box, width)} aria-hidden="true">
                      既定の位置
                    </span>
                  )}
                  {imageUrl && <img src={imageUrl} alt="" class="page-stamp" />}
                </div>
              )}
            </div>
          );
        })}
      </div>

      {/* Always present, never conditionally inserted: a live region added to the page at the
          moment it has something to say is often not announced at all. */}
      <p class="visually-hidden" aria-live="polite">
        {rect
          ? `${page} ページ目。左下から右へ ${Math.round(rect[0])}pt、上へ ${Math.round(rect[1])}pt、` +
            `幅 ${Math.round(rect[2] - rect[0])}pt、高さ ${Math.round(rect[3] - rect[1])}pt。` +
            (provisional ? "既定の位置です。" : "")
          : "署名の位置はまだ指定されていません。"}
      </p>

      <small class="note">
        {provisional
          ? "この位置に署名されます。変えたいときは、どのページでもドラッグしてください。"
          : "どのページでもドラッグすると、そのページに署名が置かれます。"}
        {rect && (
          <>
            {" "}
            現在は {page} ページ目の PDF 座標 [{rect.map((n) => Math.round(n)).join(" ")}]
            （原点は左下）。
          </>
        )}
      </small>

      <small class="note" id={helpId}>
        キーボードでも指定できます。Tab でページに入り、PageUp / PageDown で前後のページへ、
        Enter でそのページに署名を置きます。矢印キーで 4pt、Shift を押しながらで 20pt 動かし、
        Alt を押しながらの矢印キーで大きさを変えます（→ ↓ で大きく、← ↑ で小さく）。
      </small>
    </div>
  );
}

function clamp(value: number, low: number, high: number) {
  return Math.min(Math.max(value, low), high);
}

/** Canvas pixels → PDF user space, normalised so the first corner is the lower left. */
function toPdf(viewport: Viewport, box: Box): Rect {
  const [ax, ay] = viewport.convertToPdfPoint(box.x, box.y);
  const [bx, by] = viewport.convertToPdfPoint(box.x + box.w, box.y + box.h);
  return [Math.min(ax, bx), Math.min(ay, by), Math.max(ax, bx), Math.max(ay, by)];
}

/** PDF user space → canvas pixels. */
function toCanvas(viewport: Viewport, rect: Rect): Box {
  const [ax, ay] = viewport.convertToViewportPoint(rect[0], rect[1]);
  const [bx, by] = viewport.convertToViewportPoint(rect[2], rect[3]);
  return {
    x: Math.min(ax, bx),
    y: Math.min(ay, by),
    w: Math.abs(bx - ax),
    h: Math.abs(by - ay),
  };
}

/**
 * The direction in PDF user space that `[dx, dy]` on screen points in, as a unit vector.
 *
 * Asked of the viewport because a page can be rotated, in which case "right" on screen is not
 * along the x axis of the page at all. Only the direction is taken from it, never the distance:
 * the caller supplies that in points, so the zoom cannot change how far a key moves things.
 */
function pdfAxis(viewport: Viewport | undefined, dx: number, dy: number): [number, number] {
  if (!viewport) return [dx, -dy];
  const [ax, ay] = viewport.convertToPdfPoint(0, 0);
  const [bx, by] = viewport.convertToPdfPoint(dx, dy);
  const vx = bx - ax;
  const vy = by - ay;
  const length = Math.hypot(vx, vy) || 1;
  return [vx / length, vy / length];
}

/** Move the whole rectangle `amount` points along `axis`. */
function shift(rect: Rect, [ux, uy]: [number, number], amount: number): Rect {
  return [
    rect[0] + ux * amount,
    rect[1] + uy * amount,
    rect[2] + ux * amount,
    rect[3] + uy * amount,
  ];
}

/**
 * Move the edge that lies in the direction of `axis` outwards by `amount`, or inwards when it is
 * negative, leaving the opposite edge alone.
 */
function resize(rect: Rect, [ux, uy]: [number, number], amount: number, bounds: Rect): Rect {
  const out: Rect = [rect[0], rect[1], rect[2], rect[3]];
  if (Math.abs(ux) >= Math.abs(uy)) {
    if (ux >= 0) out[2] = clamp(rect[2] + amount, rect[0] + MIN_SIDE, bounds[2]);
    else out[0] = clamp(rect[0] - amount, bounds[0], rect[2] - MIN_SIDE);
  } else {
    if (uy >= 0) out[3] = clamp(rect[3] + amount, rect[1] + MIN_SIDE, bounds[3]);
    else out[1] = clamp(rect[1] - amount, bounds[1], rect[3] - MIN_SIDE);
  }
  return out;
}

/** Put a rectangle inside a page, keeping its size where the page is big enough to hold it. */
function fitInto(rect: Rect, bounds: Rect): Rect {
  const width = Math.min(rect[2] - rect[0], bounds[2] - bounds[0]);
  const height = Math.min(rect[3] - rect[1], bounds[3] - bounds[1]);
  const x = clamp(rect[0], bounds[0], bounds[2] - width);
  const y = clamp(rect[1], bounds[1], bounds[3] - height);
  return [x, y, x + width, y + height];
}

/**
 * The scale at which a whole page fits the visible area.
 *
 * The width comes from the element, which has one as soon as it exists, but the height comes from
 * the cap rather than from the element: until there are pages in it the element is only as tall as
 * its own minimum, and fitting to that would leave every page far too small to place anything on.
 */
function fitScale(pages: PageSize[], view: HTMLElement | null): number {
  if (pages.length === 0) return 1;
  const widest = Math.max(...pages.map((size) => size.width));
  const tallest = Math.max(...pages.map((size) => size.height));

  let width = FALLBACK_WIDTH;
  let height = VIEWPORT_MAX_HEIGHT;
  if (view) {
    const style = window.getComputedStyle(view);
    const inner =
      view.clientWidth -
      parseFloat(style.paddingLeft) -
      parseFloat(style.paddingRight) -
      SCROLLBAR_SLACK;
    if (inner > 0) width = inner;
    height =
      Math.min((window.innerHeight * VIEWPORT_VH) / 100, VIEWPORT_MAX_HEIGHT) -
      parseFloat(style.paddingTop) -
      parseFloat(style.paddingBottom);
  }
  return clamp(Math.min(width / widest, height / tallest), 0.1, 4);
}

/** Where the "既定の位置" label sits, kept inside the page so it cannot scroll the view sideways. */
function tagStyle(box: Box, pageWidth: number) {
  const lowest = -box.x;
  const left = clamp(0, lowest, Math.max(lowest, pageWidth - TAG_WIDTH - box.x));
  return {
    left: `${left}px`,
    // Above the rectangle where there is room for it, and just inside it where there is not.
    top: box.y >= TAG_HEIGHT ? `${-TAG_HEIGHT}px` : "0px",
  };
}
