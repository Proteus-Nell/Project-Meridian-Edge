// Guards the static page surface: the head metadata in index.html, the
// zero-JavaScript error page, and the two edge configs that serve them.
//
// Every assertion here stands in for a regression that is silent in
// development. A dev server answers every path with the app whether or not the
// edge would, so a reinstated SPA fallback looks correct locally; the CSP is
// absent under `vite dev`, so an inline <style> added to the error page renders
// perfectly right up until it is deployed; and a <meta> tag that someone tidies
// away breaks nothing that any existing test observes. None of it surfaces
// until production, which is exactly the class of bug worth a cheap unit test.
//
// Deliberately NOT asserted: that the SPA fallback's absence is correct. That
// holds only while the client has no router, and a router landing is precisely
// the change that should be free to reinstate the fallback - by editing these
// tests on purpose, with the comment in nginx.conf explaining the trade.

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

function read(relative: string): string {
  return readFileSync(fileURLToPath(new URL(relative, import.meta.url)), "utf-8");
}

const INDEX = read("../index.html");
const NOT_FOUND = read("../public/404.html");
const ROBOTS = read("../public/robots.txt");
const NGINX = read("../../deploy/nginx.conf");
const CADDY = read("../../deploy/Caddyfile");
const FAVICON = read("../public/favicon.svg");

/** Strip HTML comments before scanning: this repo's markup is heavily
 * commented, and several comments discuss the very tags being asserted. */
function stripComments(html: string): string {
  return html.replace(/<!--[\s\S]*?-->/g, "");
}

describe("index.html head metadata", () => {
  const head = stripComments(INDEX);

  it.each([
    ['name="description"', /<meta[^>]*name="description"[^>]*>/],
    ['name="robots" content="noindex"', /<meta[^>]*name="robots"[^>]*content="noindex"[^>]*>/],
    ["favicon link", /<link[^>]*rel="icon"[^>]*href="\/favicon\.svg"[^>]*>/],
    ["og:title", /<meta[^>]*property="og:title"[^>]*>/],
    ["og:description", /<meta[^>]*property="og:description"[^>]*>/],
    ["og:image", /<meta[^>]*property="og:image"[^>]*>/],
    ["og:image:alt", /<meta[^>]*property="og:image:alt"[^>]*>/],
    ["twitter:card", /<meta[^>]*name="twitter:card"[^>]*>/],
  ])("declares %s", (_label, pattern) => {
    expect(head).toMatch(pattern);
  });

  it("keeps the language attribute", () => {
    expect(head).toMatch(/<html[^>]*\blang="en"/);
  });

  it("carries a noscript fallback, since the app renders nothing without JS", () => {
    expect(head).toContain("<noscript>");
    expect(head).toMatch(/id="noscript-notice"/);
  });

  it("states the og:image dimensions unfurlers use to lay the card out", () => {
    expect(head).toMatch(/property="og:image:width"[^>]*content="1200"/);
    expect(head).toMatch(/property="og:image:height"[^>]*content="630"/);
  });
});

// `style-src 'self'` and `script-src 'self'` block both inline forms outright,
// so either one is a page that silently loses its styling or its behaviour once
// deployed. The error page is the more fragile of the two: it exists to render
// when the bundle did not, so it cannot borrow anything from the bundle.
describe.each([
  ["index.html", INDEX],
  ["public/404.html", NOT_FOUND],
])("%s obeys the page CSP", (_name, html) => {
  const markup = stripComments(html);

  it("has no inline <style> element", () => {
    expect(markup).not.toMatch(/<style[\s>]/i);
  });

  it("has no style= attribute", () => {
    expect(markup).not.toMatch(/\sstyle="/i);
  });

  it("has no inline <script> (a src= script is fine)", () => {
    expect(markup).not.toMatch(/<script(?![^>]*\bsrc=)[^>]*>/i);
  });

  it("has no inline event handler attribute", () => {
    expect(markup).not.toMatch(/\son(?:click|load|error|focus|mouseover)=/i);
  });
});

describe("public/404.html", () => {
  it("loads its stylesheet as an external file", () => {
    expect(stripComments(NOT_FOUND)).toMatch(/<link[^>]*rel="stylesheet"[^>]*href="\/404\.css"/);
  });

  it("carries no script at all, since the bundle may be what failed", () => {
    expect(stripComments(NOT_FOUND)).not.toMatch(/<script/i);
  });

  it("links back to the site root", () => {
    expect(stripComments(NOT_FOUND)).toMatch(/<a[^>]*href="\/"/);
  });

  it("is itself noindex", () => {
    expect(stripComments(NOT_FOUND)).toMatch(/name="robots"[^>]*content="noindex"/);
  });
});

describe("public/robots.txt", () => {
  // The noindex meta tag is what keeps the app out of search results. This file
  // must stay permissive: unfurlers (Slack, Discord, Signal) read robots.txt
  // before fetching a page, so a blanket disallow would strip the Open Graph
  // preview off every shared link while adding nothing against search engines.
  it("does not disallow crawling, which would break link previews", () => {
    const disallows = ROBOTS.split("\n")
      .filter((line) => !line.trimStart().startsWith("#"))
      .filter((line) => /^\s*Disallow:\s*\S/i.test(line));
    expect(disallows).toEqual([]);
  });

  it("still declares a User-agent group, so the file is well formed", () => {
    expect(ROBOTS).toMatch(/^\s*User-agent:\s*\*/m);
  });
});

describe("edge configs serve a real 404", () => {
  it("nginx does not rewrite unmatched paths to the app", () => {
    expect(NGINX).not.toMatch(/try_files[^;]*\/index\.html/);
  });

  it("nginx returns 404 and names the error page", () => {
    expect(NGINX).toMatch(/try_files\s+\$uri\s+\$uri\/\s+=404;/);
    expect(NGINX).toMatch(/error_page\s+404\s+\/404\.html;/);
  });

  it("caddy does not rewrite unmatched paths to the app", () => {
    expect(CADDY).not.toMatch(/try_files[^\n]*\/index\.html/);
  });

  it("caddy handles 404 with the error page at a 404 status", () => {
    expect(CADDY).toMatch(/handle_errors\s+404\s*\{/);
    expect(CADDY).toMatch(/rewrite\s+\*\s+\/404\.html/);
    expect(CADDY).toMatch(/status\s+404/);
  });

  // The 404 is an HTML page like any other, so it needs the same header set.
  // In nginx that is automatic (it is served from inside `location /`, and
  // every add_header there carries `always`, without which nginx drops them on
  // a 4xx). Caddy has no such inheritance, hence the shared snippet - which
  // also keeps exactly one copy of the CSP in the file for scripts/audit.py to
  // compare against nginx.conf and vite.config.ts.
  it("caddy shares one header snippet between the bundle and the error page", () => {
    expect(CADDY).toMatch(/\(static_headers\)\s*\{/);
    expect(CADDY.match(/import static_headers/g)).toHaveLength(2);
    expect(CADDY.match(/Content-Security-Policy/g)).toHaveLength(1);
  });

  it("nginx keeps `always` on the CSP so it survives onto the 404 response", () => {
    // Matched across the quoted value rather than up to the first `;`: the CSP
    // is a semicolon-separated list, so the directive's own separators come
    // long before the one that ends the nginx line.
    expect(NGINX).toMatch(/add_header Content-Security-Policy\s+"[^"]*"\s+always;/);
  });
});

// The tab icon is the emblem the app wears, which is only true for as long as
// the two are the same drawing. They live in different files - the medallion is
// markup in index.html, the favicon is a standalone image fetched by the
// browser - so nothing but a test keeps a change to one from leaving the other
// behind.
describe("favicon", () => {
  // Stripped for the same reason the head is: this file explains itself at
  // length, and the comment discusses the very things asserted below.
  const markup = stripComments(FAVICON);

  /** The `d` of the only path in an SVG-ish string, or null. */
  function pathData(svg: string): string | null {
    return /<path[^>]*\sd="([^"]+)"/.exec(svg)?.[1] ?? null;
  }

  it("draws the same glyph as the medallion's default emblem", () => {
    const medallion = /<g class="glyph glyph-gaia">([\s\S]*?)<\/g>/.exec(stripComments(INDEX))?.[1] ?? "";
    const drawn = pathData(medallion);
    expect(drawn, "index.html no longer has a glyph-gaia path").not.toBeNull();
    expect(pathData(markup)).toBe(drawn);
  });

  it("keeps the even-odd rule that makes the figure a hole rather than a shape", () => {
    expect(markup).toMatch(/fill-rule="evenodd"/);
  });

  it("names its colour literally, since a standalone image sees no CSS variables", () => {
    expect(pathData(markup)).not.toBeNull();
    expect(markup).toMatch(/fill="#[0-9a-f]{6}"/);
    expect(markup).not.toContain("var(");
  });

  // Same reason the page carries no inline <style>: the production CSP's
  // style-src is 'self', and CSS inside an SVG fetched as an image sits in a
  // murky corner of it. Attributes moot the question.
  it("carries no style element", () => {
    expect(markup).not.toMatch(/<style/);
  });
});
