// Restores the styling xterm builds at runtime, under the production CSP.
//
// xterm.css does not carry the terminal's core styling. The DOM renderer
// generates it from the live theme and appends it as <style> elements: the cell
// metrics (`white-space: pre`, the font face and size, the inline-block cell
// box), the 256-entry ANSI palette, the dim/bold/italic attributes, the text
// selection, and the cursor with its blink keyframes.
//
// deploy/nginx.conf and deploy/Caddyfile send `style-src 'self'`, which blocks
// every one of them - a generated <style> is an inline style. The deployed
// terminal therefore renders with `white-space: normal`, so the banner's column
// alignment collapses to single spaces, ANSI colours fall back to the plain
// foreground, and the cursor is painted with no styling at all. Dev serves no
// CSP, which is why it only shows up once deployed.
//
// Relaxing the CSP to 'unsafe-inline' would fix it, and is what most projects
// do. This takes the other route: a constructed CSSStyleSheet is CSSOM, not an
// inline style, so `style-src` does not apply to it. Copying each blocked
// sheet's text into document.adoptedStyleSheets restores the terminal exactly
// as xterm intended and leaves the CSP untouched.
//
// Mirroring beats reimplementing the rules in style.css. They are generated
// from the current scheme, font and size, so xterm rewrites them on every
// /settings change; a hand-maintained copy would have to duplicate xterm's own
// ANSI defaults for the schemes that do not override them (theme.ts), and would
// drift silently on the next xterm upgrade.

/** The document-shaped seam the sync step writes through, so it can be
 * exercised without a DOM (the client's tests run on node, no jsdom). */
export interface StyleSheetHost {
  adoptedStyleSheets: readonly CSSStyleSheet[];
}

/** Whether this browser can adopt a constructed stylesheet. Chrome 73+,
 * Firefox 101+, Safari 16.4+. Where it is missing there is nothing to fall back
 * to under a strict CSP, so the terminal renders as it does today rather than
 * failing. */
export function canAdoptStyleSheets(host: StyleSheetHost = document): boolean {
  return typeof CSSStyleSheet === "function" && Array.isArray(host.adoptedStyleSheets);
}

/**
 * Copy every CSP-blocked style element into an adopted stylesheet, reusing the
 * mirror already made for a given source so a theme change updates its sheet in
 * place instead of growing adoptedStyleSheets without bound.
 *
 * A source whose `sheet` is non-null was applied normally (dev, or any origin
 * without the strict CSP) and is left alone, so this is inert wherever it is
 * not needed. Pure apart from the two collections it writes to; the observer
 * wiring lives in mirrorTerminalStyles below.
 */
export function syncBlockedStyles(
  sources: Iterable<HTMLStyleElement>,
  mirrors: Map<HTMLStyleElement, CSSStyleSheet>,
  host: StyleSheetHost,
  create: () => CSSStyleSheet = () => new CSSStyleSheet(),
): void {
  for (const source of sources) {
    if (source.sheet !== null) {
      continue; // applied normally: nothing for us to do
    }
    let mirror = mirrors.get(source);
    const isNew = mirror === undefined;
    if (mirror === undefined) {
      mirror = create();
      mirrors.set(source, mirror);
    }
    try {
      mirror.replaceSync(source.textContent ?? "");
    } catch {
      // replaceSync rejects @import, which xterm never emits. A malformed sheet
      // is not worth taking the terminal down over: skip it and keep the rest.
      continue;
    }
    if (isNew) {
      host.adoptedStyleSheets = [...host.adoptedStyleSheets, mirror];
    }
  }
}

/** Stops mirroring and drops the adopted sheets this mirror added. */
export interface StyleMirror {
  /** Re-copy every blocked sheet now. Idempotent. */
  sync(): void;
  dispose(): void;
}

const INERT: StyleMirror = { sync: () => {}, dispose: () => {} };

/**
 * Mirror the style elements xterm appends inside `root` (a mounted terminal's
 * element) for as long as the terminal lives.
 *
 * The observers are deliberately narrow. xterm appends its style elements as
 * direct children of .xterm-screen, which is also the subtree the renderer
 * rewrites on every single write - so watching that subtree would fire this on
 * every line of output. Instead one childList observer per container catches a
 * style element appearing, and each style element is then watched on its own;
 * those only mutate when the theme, font or size changes.
 */
export function mirrorTerminalStyles(
  root: HTMLElement,
  host: StyleSheetHost = document,
): StyleMirror {
  if (!canAdoptStyleSheets(host) || typeof MutationObserver === "undefined") {
    return INERT;
  }

  const mirrors = new Map<HTMLStyleElement, CSSStyleSheet>();
  const observers: MutationObserver[] = [];
  const watched = new WeakSet<HTMLStyleElement>();

  const sync = (): void => {
    const styles = root.querySelectorAll("style");
    syncBlockedStyles(styles, mirrors, host);
    // xterm rewrites a sheet's textContent in place on a theme/font change,
    // which replaces its child text node - a childList mutation on the style
    // element itself, not on the container.
    for (const style of styles) {
      if (watched.has(style)) {
        continue;
      }
      watched.add(style);
      const observer = new MutationObserver(sync);
      observer.observe(style, { childList: true, characterData: true, subtree: true });
      observers.push(observer);
    }
  };

  // Direct children only: .xterm-screen holds both the style elements and the
  // rows, and the rows churn on every write.
  for (const container of [root, ...root.querySelectorAll(".xterm-screen")]) {
    const observer = new MutationObserver(sync);
    observer.observe(container, { childList: true });
    observers.push(observer);
  }

  sync();

  return {
    sync,
    dispose: () => {
      for (const observer of observers) {
        observer.disconnect();
      }
      observers.length = 0;
      const dropped = new Set(mirrors.values());
      host.adoptedStyleSheets = host.adoptedStyleSheets.filter((s) => !dropped.has(s));
      mirrors.clear();
    },
  };
}
