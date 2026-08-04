#!/usr/bin/env python3
"""Merge the three benchmark pipelines into one report.

Nothing here measures anything: every figure already exists. The suites are
produced by three tools that never converged, so the journal report only ever
contained the browser half.

  browser B1-B4        /bench in the client terminal -> JSON (download/console)
  native B1/B2 + B5    make bench-server             -> bench/out/results.json
  B5 bundle delta      make bench-bundle             -> bench/out/bundle.json

B1 and B2 are merged into one table per suite, browser beside native, because
the browser-JS versus native-C gap is the finding bench/README.md leads with
and it was previously spread across two documents for a reader to compute by
hand. B3 and B4 exist only in the browser harness and are carried through.

Run:  python bench/consolidate.py <browser.json>
      make bench-report BROWSER_JSON=<browser.json>
"""

from __future__ import annotations

import argparse
import json
import math
import sys
from pathlib import Path
from typing import Any

BENCH_DIR = Path(__file__).resolve().parent
REPO_ROOT = BENCH_DIR.parent
DEFAULT_OUT_DIR = BENCH_DIR / "out"

#: Every suite the browser harness must have run. A consolidated report that
#: quietly drops one is the failure this script exists to prevent, so a partial
#: /bench run is an error rather than a shorter document.
BROWSER_SUITES = ("B1", "B2", "B3", "B4")

BROWSER_REMEDY = (
    "Run /bench in the client terminal (no argument, so every suite runs), keep the JSON\n"
    "  it offers as a download - the browser console holds the same text as a fallback -\n"
    "  and pass that file: python bench/consolidate.py <file>"
)
SERVER_REMEDY = "Run: make bench-server"
BUNDLE_REMEDY = "Run: make bench-bundle"

#: B5 caveats, kept in the wording bench/README.md documents. The bundle JSON
#: carries no note of its own, and the footprint's note stops short of saying
#: what the number is not.
BUNDLE_CAVEAT = (
    "Each row is a standalone bundled size, not the marginal cost of adding that library to "
    "this client: `@noble/hashes` is already a dependency, so modules shared with it are "
    "counted here but shipped either way. Read it as a like-for-like library comparison and "
    "an upper bound on the true delta."
)
FOOTPRINT_CAVEAT = (
    "This is not RSS. `tracemalloc` sees Python-heap allocations only, so the database engine "
    "and OpenSSL's native memory fall outside it: read the figure as reproducible and relative, "
    "not as absolute process memory."
)
BREAKDOWN_CAVEAT = (
    "Composition traced by hand from `client/src/crypto/kx.ts`, not instrumented. Predicted is "
    "the sum of per-op B1/B2 browser medians - the median of a sum is not the sum of medians, so "
    "read it as an estimate, and note that B1/B2 batch their samples where B4 times one operation "
    "at a time. The residual is everything the composition does not name: SHA-512 transcript and "
    "prekey hashing, HKDF, XChaCha20-Poly1305, framing, allocation. Line items are rounded for "
    "display while the totals come from unrounded medians, so a column may not add up in its last "
    "digit. The primitive prices are the browser figures, not the native ones."
)
PRECISION_NOTE = (
    "Both columns are medians, formatted to three significant figures. The browser figures "
    "carry a quantisation floor (`performance.now()` is clamped, divided down by the batch "
    "size - the browser report states the floor per row); the native figures come from "
    "`perf_counter` and have none."
)


class MissingInput(Exception):
    """An input the report cannot be honest without."""


# ----- loading -------------------------------------------------------------


def load_json(path: Path, what: str, remedy: str) -> dict[str, Any]:
    """Read one input, or explain exactly how to produce it. Every failure here
    is a stop: a partial report is the bug, not the fallback."""
    if not path.exists():
        raise MissingInput(f"{what} not found at {path}.\n  {remedy}")
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise MissingInput(f"{what} at {path} could not be read: {exc}\n  {remedy}") from exc
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        raise MissingInput(f"{what} at {path} is not valid JSON: {exc}\n  {remedy}") from exc
    if not isinstance(payload, dict):
        raise MissingInput(
            f"{what} at {path} is not a benchmark report (expected a JSON object).\n  {remedy}"
        )
    return payload


def _results_by_suite(payload: dict[str, Any], path: Path, what: str, remedy: str) -> dict[str, Any]:
    results = payload.get("results")
    if not isinstance(results, list) or not results:
        raise MissingInput(f"{what} at {path} has no `results` array.\n  {remedy}")
    return {
        row["suite"]: row
        for row in results
        if isinstance(row, dict) and isinstance(row.get("suite"), str)
    }


def browser_suites(payload: dict[str, Any], path: Path) -> dict[str, Any]:
    by_suite = _results_by_suite(payload, path, "Browser results", BROWSER_REMEDY)
    missing = [suite for suite in BROWSER_SUITES if suite not in by_suite]
    if missing:
        raise MissingInput(
            f"Browser results at {path} are missing {', '.join(missing)}.\n"
            "  A consolidated report must not quietly omit a suite.\n"
            f"  {BROWSER_REMEDY}"
        )
    return by_suite


def native_suites(payload: dict[str, Any], path: Path) -> dict[str, Any]:
    by_suite = _results_by_suite(payload, path, "Server results", SERVER_REMEDY)
    missing = [suite for suite in ("B1", "B2") if suite not in by_suite]
    if missing:
        raise MissingInput(
            f"Server results at {path} are missing {', '.join(missing)}.\n  {SERVER_REMEDY}"
        )
    if not isinstance(payload.get("footprint"), dict):
        raise MissingInput(
            f"Server results at {path} carry no B5 footprint.\n  {SERVER_REMEDY}"
        )
    return by_suite


# ----- formatting ----------------------------------------------------------


def _sig3(value: float) -> str:
    """Three significant figures, never exponential - the precision rule the
    browser report uses, applied to both columns so neither reads as finer."""
    rounded = float(f"{value:.3g}")
    if rounded == 0:
        return "0"
    magnitude = math.floor(math.log10(abs(rounded)))
    return f"{rounded:.{max(0, 2 - magnitude)}f}"


def fmt_us(microseconds: float | None) -> str:
    if microseconds is None or microseconds <= 0:
        return "-"
    if microseconds >= 1000:
        return f"{_sig3(microseconds / 1000)} ms"
    return f"{_sig3(microseconds)} us"


def fmt_factor(numerator: float | None, denominator: float | None) -> str:
    if numerator is None or denominator is None or denominator <= 0:
        return "-"
    factor = numerator / denominator
    return f"x{round(factor)}" if factor >= 10 else f"x{factor:.1f}"


def fmt_bytes(value: float | None) -> str:
    return "-" if value is None else f"{round(value):,}"


def md_table(headers: list[str], rows: list[list[str]]) -> list[str]:
    return [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join("---" for _ in headers) + " |",
        *["| " + " | ".join(row) + " |" for row in rows],
    ]


# ----- statistic extraction ------------------------------------------------
#
# The two harnesses report different units - the browser in milliseconds
# (`medianMs`), the server in microseconds (`median_us`). Everything is
# normalised to microseconds here so a merged row compares like with like.


def browser_median_us(stats: Any) -> float | None:
    if not isinstance(stats, dict):
        return None
    value = stats.get("medianMs")
    return float(value) * 1000 if isinstance(value, (int, float)) else None


def native_median_us(stats: Any) -> float | None:
    if not isinstance(stats, dict):
        return None
    value = stats.get("median_us")
    return float(value) if isinstance(value, (int, float)) else None


def _rows_by_op(result: Any) -> dict[str, dict[str, Any]]:
    rows = result.get("rows") if isinstance(result, dict) else None
    if not isinstance(rows, list):
        return {}
    return {
        row["op"]: row
        for row in rows
        if isinstance(row, dict) and isinstance(row.get("op"), str)
    }


def _display_path(path: Path) -> str:
    """Repo-relative, posix-style. A report that quotes an absolute path reads
    differently on every machine and leaks the author's directory tree."""
    try:
        return path.resolve().relative_to(REPO_ROOT).as_posix()
    except ValueError:
        return path.as_posix()


def _browser_counts(result: dict[str, Any]) -> str | None:
    """What the browser harness actually ran. The browser report states this
    above every table; the merge would otherwise drop it."""
    samples = result.get("samples")
    if not isinstance(samples, (int, float)):
        return None
    text = f"{int(samples):,} samples per row"
    warmup = result.get("warmup")
    if isinstance(warmup, (int, float)):
        text += f" after {int(warmup):,} discarded warm-up"
    return f"{text}, each sample timing a batch of calls"


def _native_counts(result: dict[str, Any]) -> str | None:
    """The server harness records its count per measurement rather than per
    suite, so it is read back off the first row."""
    rows = result.get("rows")
    if not isinstance(rows, list) or not rows or not isinstance(rows[0], dict):
        return None
    stats = rows[0].get("pqc")
    iters = stats.get("iters") if isinstance(stats, dict) else None
    if not isinstance(iters, (int, float)):
        return None
    return f"{int(iters):,} samples per row, one call per sample (no batching needed)"


def _gap_sentence(name: str, ratios: list[float]) -> str | None:
    """State the JS/native gap for one algorithm across its operations."""
    if not ratios:
        return None
    low, high = min(ratios), max(ratios)
    if round(low) == round(high):
        return f"{name} runs about x{round(low)} slower in the browser than through OpenSSL"
    return f"{name} runs x{round(low)}-x{round(high)} slower in the browser than through OpenSSL"


# ----- sections ------------------------------------------------------------


def render_latency(suite: str, browser: dict[str, Any], native: dict[str, Any]) -> list[str]:
    """One table per suite, both environments side by side, plus the derived
    JS/native ratio the two separate reports never let anyone see."""
    pqc_name = str(browser.get("pqcName") or native.get("pqc_name") or "PQC")
    classical_name = str(browser.get("classicalName") or native.get("classical_name") or "classical")
    title = str(browser.get("title") or f"{suite} - latency")

    browser_rows = _rows_by_op(browser)
    native_rows = _rows_by_op(native)
    ops = list(browser_rows) + [op for op in native_rows if op not in browser_rows]

    table: list[list[str]] = []
    pqc_ratios: list[float] = []
    classical_ratios: list[float] = []
    for op in ops:
        b_pqc = browser_median_us(browser_rows.get(op, {}).get("pqc"))
        b_classical = browser_median_us(browser_rows.get(op, {}).get("classical"))
        n_pqc = native_median_us(native_rows.get(op, {}).get("pqc"))
        n_classical = native_median_us(native_rows.get(op, {}).get("classical"))
        if b_pqc is not None and n_pqc is not None and n_pqc > 0:
            pqc_ratios.append(b_pqc / n_pqc)
        if b_classical is not None and n_classical is not None and n_classical > 0:
            classical_ratios.append(b_classical / n_classical)
        table.append(
            [
                op,
                fmt_us(b_pqc),
                fmt_us(b_classical),
                fmt_factor(b_pqc, b_classical),
                fmt_us(n_pqc),
                fmt_us(n_classical),
                fmt_factor(n_pqc, n_classical),
                fmt_factor(b_pqc, n_pqc),
            ]
        )

    lines = [f"## {title}", ""]
    lines += md_table(
        [
            "op",
            f"browser {pqc_name}",
            f"browser {classical_name}",
            "browser factor",
            f"native {pqc_name}",
            f"native {classical_name}",
            "native factor",
            "JS/native (PQC)",
        ],
        table,
    )
    gaps = [
        sentence
        for sentence in (
            _gap_sentence(pqc_name, pqc_ratios),
            _gap_sentence(classical_name, classical_ratios),
        )
        if sentence is not None
    ]
    if gaps:
        lines += ["", f"**JS/native gap.** {'; '.join(gaps)}."]
    counts = [
        f"{label}: {text}"
        for label, text in (
            ("Browser", _browser_counts(browser)),
            ("Native", _native_counts(native)),
        )
        if text is not None
    ]
    if counts:
        lines += ["", f"**Run counts.** {'. '.join(counts)}."]
    lines += ["", f"_{PRECISION_NOTE}_"]
    for source, label in ((browser, "browser"), (native, "native")):
        note = source.get("note")
        if isinstance(note, str) and note:
            lines += ["", f"_{label}: {note}_"]
    return lines


def render_sizes(result: dict[str, Any]) -> list[str]:
    """B3, carried through from the browser harness unchanged."""
    rows = result.get("rows")
    table = [
        [
            str(row.get("object", "")),
            fmt_bytes(row.get("classicalBytes")),
            fmt_bytes(row.get("pqcBytes")),
            fmt_factor(row.get("pqcBytes"), row.get("classicalBytes")),
            str(row.get("basis", "-")),
        ]
        for row in rows
        if isinstance(row, dict)
    ] if isinstance(rows, list) else []

    lines = [f"## {result.get('title', 'B3 - size overhead (bytes)')}", ""]
    lines += ["Browser harness only. These are byte counts rather than timings, so they do not"]
    lines += ["vary with the runtime; there is no native counterpart to merge.", ""]
    lines += md_table(["object", "classical", "pure PQC", "factor", "PQC basis"], table)
    note = result.get("note")
    if isinstance(note, str) and note:
        lines += ["", f"_{note}_"]
    return lines


def render_protocol(result: dict[str, Any]) -> list[str]:
    """B4, carried through from the browser harness unchanged."""
    rows = result.get("rows")
    table: list[list[str]] = []
    if isinstance(rows, list):
        for row in rows:
            if not isinstance(row, dict):
                continue
            stats = row.get("stats") if isinstance(row.get("stats"), dict) else {}
            ops_per_sec = stats.get("opsPerSec")
            rate = "-"
            if row.get("display") == "throughput" and isinstance(ops_per_sec, (int, float)):
                rate = f"{round(ops_per_sec):,} {row.get('unit', 'op')}/s"
            table.append(
                [
                    str(row.get("metric", "")),
                    fmt_us(browser_median_us(stats)),
                    fmt_us(_scaled(stats, "p95Ms")),
                    fmt_us(_scaled(stats, "meanMs")),
                    rate,
                ]
            )

    lines = [f"## {result.get('title', 'B4 - protocol level')}", ""]
    lines += ["Browser harness only: it drives the real kx/ratchet paths, which exist in the"]
    lines += ["client. Crypto cost only - no network RTT.", ""]
    lines += md_table(["metric", "median", "p95", "mean", "mean throughput"], table)
    counts = _browser_counts(result)
    if counts is not None:
        # B4 caps its counts well below B1/B2's, so a merged document that did
        # not repeat them would invite a comparison across different sample
        # sizes - the thing the browser report was changed to prevent.
        lines += ["", f"**Run counts.** Browser: {counts}."]
    note = result.get("note")
    if isinstance(note, str) and note:
        lines += ["", f"_{note}_"]
    lines += render_breakdown(result)
    return lines


def _signed_ms(milliseconds: float) -> str:
    if milliseconds == 0:
        return "0"
    formatted = fmt_us(abs(milliseconds) * 1000)
    return f"-{formatted}" if milliseconds < 0 else f"+{formatted}"


def render_breakdown(result: dict[str, Any]) -> list[str]:
    """B4's rows priced against the B1/B2 primitives. Carried through from the
    browser report: it answers "where does the time go" before a reviewer asks,
    and it is the merged document's own soundness check - the residual is what
    the primitive composition fails to account for."""
    entries = result.get("breakdown")
    if not isinstance(entries, list) or not entries:
        # Absent when /bench ran B4 alone. Say so rather than leaving a reader
        # to wonder whether the decomposition was tried and failed.
        return [
            "",
            "_No primitive breakdown in this run: it prices B4's rows against the B1/B2 medians, "
            "which are only available when /bench runs every suite._",
        ]

    table: list[list[str]] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        components = entry.get("components")
        if isinstance(components, list):
            for index, component in enumerate(components):
                if not isinstance(component, dict):
                    continue
                count = component.get("count")
                each_ms = component.get("eachMs")
                count_value = float(count) if isinstance(count, (int, float)) else 0.0
                each_value = float(each_ms) if isinstance(each_ms, (int, float)) else 0.0
                table.append(
                    [
                        str(entry.get("metric", "")) if index == 0 else "",
                        str(component.get("label", "")),
                        f"{int(count_value)}",
                        fmt_us(each_value * 1000),
                        fmt_us(count_value * each_value * 1000),
                    ]
                )
        predicted = entry.get("predictedMs")
        measured = entry.get("measuredMs")
        if not isinstance(predicted, (int, float)) or not isinstance(measured, (int, float)):
            continue
        residual = float(measured) - float(predicted)
        share = (residual / float(measured) * 100) if measured else 0.0
        table.append(["", "predicted total", "", "", fmt_us(float(predicted) * 1000)])
        table.append(["", "measured median", "", "", fmt_us(float(measured) * 1000)])
        table.append(["", "residual", "", "", f"{_signed_ms(residual)} ({share:.1f}%)"])

    lines = ["", "### Where the time goes (B4 rows priced from the B1/B2 primitives)", ""]
    lines += md_table(["metric", "component", "count", "each", "subtotal"], table)
    lines += ["", f"_{BREAKDOWN_CAVEAT}_"]
    return lines


def _scaled(stats: dict[str, Any], key: str) -> float | None:
    value = stats.get(key)
    return float(value) * 1000 if isinstance(value, (int, float)) else None


def render_footprint(bundle: dict[str, Any], footprint: dict[str, Any]) -> list[str]:
    """B5's two halves, which have never appeared in the same document."""
    lines = ["## B5 - footprint", "", "### Frontend bundle size", ""]
    rows = bundle.get("rows")
    table = [
        [
            str(row.get("library", "")),
            f"{round(float(row.get('raw', 0))) / 1024:.1f} kB",
            f"{round(float(row.get('gzip', 0))) / 1024:.1f} kB",
        ]
        for row in rows
        if isinstance(row, dict)
    ] if isinstance(rows, list) else []
    lines += md_table(["library", "minified", "gzipped"], table)
    if isinstance(rows, list) and len(rows) >= 2 and all(isinstance(r, dict) for r in rows[:2]):
        pqc_gzip = float(rows[0].get("gzip", 0))
        classical_gzip = float(rows[1].get("gzip", 0))
        if classical_gzip > 0:
            delta = (pqc_gzip - classical_gzip) / 1024
            lines += [
                "",
                f"PQC versus classical, standalone and gzipped: {delta:+.1f} kB "
                f"({pqc_gzip / classical_gzip:.1f}x).",
            ]
    lines += ["", f"_{BUNDLE_CAVEAT}_", "", "### Server memory per active session", ""]
    lines += md_table(
        ["sessions", "bytes/session", "total bytes"],
        [
            [
                fmt_bytes(footprint.get("sessions")),
                fmt_bytes(footprint.get("bytes_per_session")),
                fmt_bytes(footprint.get("total_bytes")),
            ]
        ],
    )
    note = footprint.get("note")
    if isinstance(note, str) and note:
        lines += ["", f"_{note}_"]
    lines += ["", f"_{FOOTPRINT_CAVEAT}_"]
    return lines


def render_provenance(
    browser: dict[str, Any],
    server: dict[str, Any],
    paths: dict[str, Path],
) -> list[str]:
    """Where every number came from. Three pipelines merged into one document
    is exactly when a reader needs to be able to trace one back."""
    lines = ["## Provenance", ""]
    environment = server.get("environment")
    native_env = "unknown"
    if isinstance(environment, dict):
        native_env = (
            f"{environment.get('implementation', '?')} {environment.get('python', '?')} on "
            f"{environment.get('platform', '?')}, {environment.get('library', '?')}"
        )
    config = browser.get("config")
    browser_config = json.dumps(config, sort_keys=True) if isinstance(config, dict) else "unknown"
    lines += md_table(
        ["source", "file", "detail"],
        [
            [
                "browser B1-B4",
                f"`{_display_path(paths['browser'])}`",
                f"generated {browser.get('generatedAt', 'unknown')}, config {browser_config}",
            ],
            ["native B1/B2 + B5 footprint", f"`{_display_path(paths['server'])}`", native_env],
            [
                "B5 bundle",
                f"`{_display_path(paths['bundle'])}`",
                "Vite production minifier, gzipped",
            ],
        ],
    )
    return lines


def consolidate(
    browser: dict[str, Any],
    server: dict[str, Any],
    bundle: dict[str, Any],
    paths: dict[str, Path],
) -> str:
    browser_by_suite = browser_suites(browser, paths["browser"])
    native_by_suite = native_suites(server, paths["server"])
    footprint = server["footprint"]

    lines = [
        "# Meridian Edge consolidated benchmark report",
        "",
        "Every suite in one document: browser B1-B4, native B1/B2, and both halves of B5.",
        "Merged by `bench/consolidate.py`; no measurement is taken here.",
        "",
    ]
    lines += render_provenance(browser, server, paths)
    for suite in ("B1", "B2"):
        lines += [""]
        lines += render_latency(suite, browser_by_suite[suite], native_by_suite[suite])
    lines += [""]
    lines += render_sizes(browser_by_suite["B3"])
    lines += [""]
    lines += render_protocol(browser_by_suite["B4"])
    lines += [""]
    lines += render_footprint(bundle, footprint)
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Merge the browser, native and bundle benchmark outputs into one report."
    )
    parser.add_argument("browser", type=Path, help="browser results JSON saved from /bench")
    parser.add_argument(
        "--server", type=Path, default=DEFAULT_OUT_DIR / "results.json", help="server results JSON"
    )
    parser.add_argument(
        "--bundle", type=Path, default=DEFAULT_OUT_DIR / "bundle.json", help="bundle sizes JSON"
    )
    parser.add_argument(
        "--out", type=Path, default=DEFAULT_OUT_DIR / "consolidated.md", help="report to write"
    )
    args = parser.parse_args(argv)

    try:
        browser = load_json(args.browser, "Browser results", BROWSER_REMEDY)
        server = load_json(args.server, "Server results", SERVER_REMEDY)
        bundle = load_json(args.bundle, "Bundle sizes", BUNDLE_REMEDY)
        markdown = consolidate(
            browser,
            server,
            bundle,
            {"browser": args.browser, "server": args.server, "bundle": args.bundle},
        )
    except MissingInput as exc:
        print(f"consolidate: {exc}", file=sys.stderr)
        return 1

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(markdown, encoding="utf-8")
    print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
