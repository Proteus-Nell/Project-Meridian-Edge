"""Tests for the benchmark harnesses in bench/.

Run:  python -m pytest bench/
The pure stats are asserted exactly; the suites run with a tiny sample count
just to prove they execute and shape their results. consolidate.py's merge is
tested against fixture JSONs, including every way an input can go missing.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from consolidate import (  # type: ignore[import-not-found]
    BREAKDOWN_CAVEAT,
    BROWSER_REMEDY,
    BUNDLE_CAVEAT,
    BUNDLE_REMEDY,
    FOOTPRINT_CAVEAT,
    SERVER_REMEDY,
)
from consolidate import main as consolidate_main  # type: ignore[import-not-found]
from server_bench import (  # type: ignore[import-not-found]
    NOTE_B1,
    _to_json,
    bench_b1,
    bench_b2,
    bench_b5_memory,
    render_markdown,
    render_terminal,
    summarize,
)


def test_summarize_nearest_rank() -> None:
    stats = summarize("t", [10, 1, 3, 5, 2, 9, 4, 8, 6, 7])
    assert stats.iters == 10
    assert stats.median_us == 5.5  # statistics.median of 10 elements averages the middle two
    assert stats.p95_us == 10  # nearest-rank 95th of 10
    assert stats.min_us == 1
    assert abs(stats.mean_us - 5.5) < 1e-9


def test_summarize_empty() -> None:
    stats = summarize("empty", [])
    assert stats.iters == 0
    assert stats.median_us == 0.0
    assert stats.ops_per_sec == 0.0
    # The empty branch builds Stats by keyword. Positionally, inserting a field
    # would shift every float along and leave an int in median_us silently.
    assert isinstance(stats.median_us, float)


def test_summarize_records_the_warmup_it_was_given() -> None:
    """A sample count means little without the warm-up beside it. Handing over
    a list directly warms nothing up, so that case records zero rather than
    inheriting the module default."""
    assert summarize("t", [1.0, 2.0, 3.0]).warmup == 0
    assert summarize("empty", []).warmup == 0
    assert summarize("t", [1.0, 2.0, 3.0], warmup=7).warmup == 7


def test_b1_runs_and_shapes_results() -> None:
    result = bench_b1(iters=3)
    assert result.suite == "B1"
    assert [row.op for row in result.rows] == ["keygen", "encaps", "decaps"]
    assert all(row.pqc.iters == 3 for row in result.rows)


def test_suites_record_the_warmup_they_ran() -> None:
    """timeit discards the warm-up runs, so nothing downstream can recover the
    count by inspection - it has to travel with the measurement."""
    b1 = bench_b1(iters=3, warmup=2)
    assert all(row.pqc.warmup == 2 for row in b1.rows)
    assert all(row.classical.warmup == 2 for row in b1.rows if row.classical is not None)
    b2 = bench_b2(iters=3, warmup=4)
    assert all(row.pqc.warmup == 4 for row in b2.rows)


def test_b1_measures_the_shared_x25519_baseline_once() -> None:
    """X25519 has no split encaps/decaps, so one exchange() is the baseline for
    both ML-KEM halves. It is measured once and reported once - carrying it on
    the decaps row too would read as a second measurement nobody took."""
    result = bench_b1(iters=3)
    by_op = {row.op: row for row in result.rows}
    assert by_op["keygen"].classical is not None
    assert by_op["encaps"].classical is not None
    assert by_op["decaps"].classical is None
    # The blank cell is only honest if the explanation ships with it. Asserting
    # the constant, not a phrase from it: a rewrite updates both sides at once
    # and this still fails if the disclosure is dropped.
    assert result.note == NOTE_B1


def test_b1_renders_the_absent_classical_cell_blank_everywhere() -> None:
    result = bench_b1(iters=3)

    # Terminal: three blank cells, and the row still splits into six columns.
    term = render_terminal([result])

    def cells(op: str) -> list[str]:
        line = next(line for line in term.splitlines() if line.strip().startswith(op))
        return re.split(r"\s{2,}", line.strip())

    assert cells("decaps")[-3:] == ["-", "-", "-"]
    assert len(cells("decaps")) == len(cells("encaps")) == 6
    assert "note:" in term

    # Markdown: same three blanks, table stays six columns wide.
    md = render_markdown([result])
    decaps = next(line for line in md.splitlines() if line.startswith("| decaps |"))
    assert decaps.endswith("| - | - | - |")
    assert len(decaps.split("|")) == 8  # 6 cells + leading/trailing empties
    assert result.note is not None and f"_{result.note}_" in md

    # JSON: an explicit null, never a repeat of the encaps figure.
    payload = json.loads(_to_json([result]))
    json_rows = payload["results"][0]["rows"]
    assert json_rows[1]["classical"] is not None
    assert json_rows[2]["classical"] is None
    assert payload["results"][0]["note"] == result.note


def test_to_json_round_trips_a_real_b1_result() -> None:
    """B1 is the suite with a None classical cell, so this covers that path as
    well as the payload's shape. `note` belongs to the result: a LatencyRow has
    only op/pqc/classical, and reaching for `row.note` would raise here."""
    payload = json.loads(_to_json([bench_b1(iters=3, warmup=2)]))
    result = payload["results"][0]
    assert result["suite"] == "B1"
    assert isinstance(result["note"], str) and result["note"]
    assert all("note" not in row for row in result["rows"])
    assert [row["op"] for row in result["rows"]] == ["keygen", "encaps", "decaps"]
    assert result["rows"][2]["classical"] is None
    # The counts travel in the payload, which is what consolidate.py reads.
    assert result["rows"][0]["pqc"]["iters"] == 3
    assert result["rows"][0]["pqc"]["warmup"] == 2


def test_headings_state_both_counts_on_both_surfaces() -> None:
    """The heading is an f-string over the run counts. A brace turning into a
    parenthesis would render the expression as literal source into a journal
    artifact, which no other assertion in this file would notice."""
    result = bench_b1(iters=7, warmup=3)
    for render in (render_markdown, render_terminal):
        text = render([result])
        heading = next(line for line in text.splitlines() if "median / p95 over" in line)
        assert "7" in heading and "3" in heading
        assert "r.rows[0]" not in text
        assert "{" not in heading and "}" not in heading


def test_b2_runs_and_renders_markdown() -> None:
    result = bench_b2(iters=3)
    assert result.pqc_name == "ML-DSA-65"
    md = render_markdown([result])
    assert "B2 - signature primitive latency" in md
    assert "| verify |" in md


def test_b5_memory_measures_per_session_footprint() -> None:
    fp = bench_b5_memory(sessions=100)
    assert fp.suite == "B5"
    assert fp.sessions == 100
    assert fp.total_bytes > 0
    assert fp.bytes_per_session > 0
    md = render_markdown([bench_b2(iters=3)], fp)
    assert "B5 - server footprint" in md


# ----- consolidate.py ------------------------------------------------------
#
# The merge exists because three pipelines never converged, so the journal
# report only ever held the browser half. The fixtures below are deliberately
# tiny with round numbers: what matters is that both environments land in one
# row, that the derived JS/native ratio is arithmetically right, and that a
# missing input stops the run rather than yielding a report that silently drops
# a suite.


def _browser_fixture(suites: tuple[str, ...] = ("B1", "B2", "B3", "B4")) -> dict[str, object]:
    def stats(median_ms: float) -> dict[str, object]:
        return {
            "label": "op",
            "iters": 10,
            "batch": 32,
            "medianMs": median_ms,
            "p95Ms": median_ms * 2,
            "meanMs": median_ms * 1.5,
            "minMs": median_ms,
            "opsPerSec": 1000 / (median_ms * 1.5),
            "tickMs": 0.003125,
        }

    available: dict[str, object] = {
        "B1": {
            "kind": "latency",
            "suite": "B1",
            "title": "B1 - KEM primitive latency",
            "pqcName": "ML-KEM-768",
            "classicalName": "X25519",
            "samples": 10,
            "warmup": 2,
            "note": "browser B1 note",
            "rows": [
                # 0.4 ms browser against 40 us native is exactly x10.
                {"op": "keygen", "pqc": stats(0.4), "classical": stats(0.8)},
                # decaps carries no classical cell at all, on either side.
                {"op": "decaps", "pqc": stats(0.8)},
            ],
        },
        "B2": {
            "kind": "latency",
            "suite": "B2",
            "title": "B2 - signature primitive latency",
            "pqcName": "ML-DSA-65",
            "classicalName": "Ed25519",
            "samples": 10,
            "warmup": 2,
            "rows": [{"op": "sign", "pqc": stats(6.0), "classical": stats(0.03)}],
        },
        "B3": {
            "kind": "size",
            "suite": "B3",
            "title": "B3 - size overhead (bytes)",
            "note": "browser B3 note",
            "rows": [
                {
                    "object": "KEM/DH public key",
                    "classicalBytes": 32,
                    "pqcBytes": 1184,
                    "basis": "measured",
                }
            ],
        },
        "B4": {
            "kind": "protocol",
            "suite": "B4",
            "title": "B4 - protocol level",
            "samples": 10,
            "warmup": 2,
            "note": "browser B4 note",
            "breakdown": [
                {
                    "metric": "handshake round-trip",
                    "components": [
                        {"label": "ML-DSA-65 verify", "count": 3, "eachMs": 1.5},
                        {"label": "ML-KEM-768 encaps", "count": 2, "eachMs": 0.5},
                    ],
                    "predictedMs": 5.5,
                    "measuredMs": 6.0,
                }
            ],
            "rows": [
                {
                    "metric": "handshake round-trip",
                    "stats": stats(12.0),
                    "display": "latency",
                    "unit": "op",
                },
                {
                    "metric": "ratchet message (alternating turns)",
                    "stats": stats(2.0),
                    "display": "throughput",
                    "unit": "msg",
                },
            ],
        },
    }
    return {
        "generatedAt": "2026-01-01T00:00:00Z",
        "config": {"warmup": 2, "iters": 10, "yieldEvery": 0},
        "results": [available[suite] for suite in suites],
    }


def _server_fixture() -> dict[str, object]:
    def stats(median_us: float) -> dict[str, object]:
        return {
            "label": "op",
            "iters": 10,
            "warmup": 5,
            "median_us": median_us,
            "p95_us": median_us * 2,
            "mean_us": median_us,
            "min_us": median_us,
            "ops_per_sec": 1_000_000 / median_us,
        }

    return {
        "environment": {
            "python": "3.14.3",
            "implementation": "CPython",
            "platform": "Windows-11",
            "library": "pyca/cryptography (OpenSSL)",
        },
        "results": [
            {
                "suite": "B1",
                "title": "B1 - KEM primitive latency",
                "pqc_name": "ML-KEM-768",
                "classical_name": "X25519",
                "note": "native B1 note",
                "rows": [
                    {"op": "keygen", "pqc": stats(40.0), "classical": stats(20.0)},
                    {"op": "decaps", "pqc": stats(50.0), "classical": None},
                ],
            },
            {
                "suite": "B2",
                "title": "B2 - signature primitive latency",
                "pqc_name": "ML-DSA-65",
                "classical_name": "Ed25519",
                "rows": [{"op": "sign", "pqc": stats(500.0), "classical": stats(25.0)}],
            },
        ],
        "footprint": {
            "suite": "B5",
            "title": "B5 - server footprint (per active session)",
            "sessions": 100,
            "total_bytes": 218_800,
            "bytes_per_session": 2188.0,
            "note": "Python-heap (tracemalloc) for the SessionToken object + hashed token",
        },
    }


def _bundle_fixture() -> dict[str, object]:
    return {
        "suite": "B5",
        "metric": "bundle-size",
        "rows": [
            {"library": "@noble/post-quantum (ML-KEM + ML-DSA)", "raw": 30_720, "gzip": 10_240},
            {"library": "@noble/curves (X25519 + Ed25519)", "raw": 40_960, "gzip": 12_800},
        ],
    }


def _write_inputs(tmp_path: Path, **overrides: object) -> dict[str, Path]:
    """Lay down the three inputs. A None override removes that file, which is
    how the missing-input paths are exercised."""
    defaults: dict[str, object] = {
        "browser": _browser_fixture(),
        "server": _server_fixture(),
        "bundle": _bundle_fixture(),
    }
    names = {"browser": "browser.json", "server": "results.json", "bundle": "bundle.json"}
    paths: dict[str, Path] = {}
    for key, filename in names.items():
        path = tmp_path / filename
        payload = overrides[key] if key in overrides else defaults[key]
        if payload is None:
            path.unlink(missing_ok=True)
        else:
            path.write_text(json.dumps(payload), encoding="utf-8")
        paths[key] = path
    return paths


def _run(tmp_path: Path, paths: dict[str, Path]) -> tuple[int, Path]:
    out = tmp_path / "consolidated.md"
    code = consolidate_main(
        [
            str(paths["browser"]),
            "--server",
            str(paths["server"]),
            "--bundle",
            str(paths["bundle"]),
            "--out",
            str(out),
        ]
    )
    return code, out


def test_consolidate_merges_both_environments_into_one_row(tmp_path: Path) -> None:
    code, out = _run(tmp_path, _write_inputs(tmp_path))
    assert code == 0
    report = out.read_text(encoding="utf-8")

    # One B1 table with both environments in it, not two tables to compare by eye.
    assert report.count("## B1 - KEM primitive latency") == 1
    assert (
        "| op | browser ML-KEM-768 | browser X25519 | browser factor "
        "| native ML-KEM-768 | native X25519 | native factor | JS/native (PQC) |"
    ) in report
    lines = report.splitlines()
    # 0.4 ms browser over 40 us native is x10; browser 0.4 against 0.8 is x0.5.
    assert (
        next(line for line in lines if line.startswith("| keygen |"))
        == "| keygen | 400 us | 800 us | x0.5 | 40.0 us | 20.0 us | x2.0 | x10 |"
    )
    # A missing classical cell stays blank on both sides - never a zero.
    assert (
        next(line for line in lines if line.startswith("| decaps |"))
        == "| decaps | 800 us | - | - | 50.0 us | - | - | x16 |"
    )
    # The gap is also stated in prose, which is the finding being surfaced.
    assert "**JS/native gap.**" in report
    assert "x10-x16" in report  # 0.4 ms / 40 us and 0.8 ms / 50 us, rounded
    # Both harnesses' own notes survive the merge, each attributed.
    assert "_browser: browser B1 note_" in report
    assert "_native: native B1 note_" in report


def test_consolidate_carries_browser_only_suites_and_both_b5_halves(tmp_path: Path) -> None:
    code, out = _run(tmp_path, _write_inputs(tmp_path))
    assert code == 0
    report = out.read_text(encoding="utf-8")

    # B3/B4 are browser-only and come through with their labelling intact.
    assert "| KEM/DH public key | 32 | 1,184 | x37 | measured |" in report
    assert "| handshake round-trip | 12.0 ms | 24.0 ms | 18.0 ms | - |" in report
    assert (
        "| ratchet message (alternating turns) | 2.00 ms | 4.00 ms | 3.00 ms | 333 msg/s |"
        in report
    )
    assert "_browser B3 note_" in report
    assert "_browser B4 note_" in report

    # B4's primitive breakdown answers "where does the time go", so the merged
    # document - the one anybody actually reads - has to carry it too.
    assert "### Where the time goes (B4 rows priced from the B1/B2 primitives)" in report
    assert "| handshake round-trip | ML-DSA-65 verify | 3 | 1.50 ms | 4.50 ms |" in report
    assert "|  | ML-KEM-768 encaps | 2 | 500 us | 1.00 ms |" in report
    assert "|  | predicted total |  |  | 5.50 ms |" in report
    assert "|  | measured median |  |  | 6.00 ms |" in report
    assert "|  | residual |  |  | +500 us (8.3%) |" in report
    assert BREAKDOWN_CAVEAT in report

    # B5's two halves finally share a document, each carrying its caveat.
    assert "## B5 - footprint" in report
    assert "### Frontend bundle size" in report
    assert "### Server memory per active session" in report
    assert "| 100 | 2,188 | 218,800 |" in report
    assert FOOTPRINT_CAVEAT in report
    assert BUNDLE_CAVEAT in report
    # The harness's own note survives alongside the added caveat, rather than
    # one silently replacing the other.
    assert "Python-heap (tracemalloc) for the SessionToken object" in report

    # The merge must not drop the sample/warm-up disclosure the individual
    # reports carry - B4's counts are capped well below B1/B2's.
    counts = next(line for line in report.splitlines() if line.startswith("**Run counts.**"))
    assert "Browser: 10 samples per row after 2 discarded warm-up" in counts
    assert "Native: 10 samples per row" in counts and "after 5 discarded warm-up" in counts

    # Provenance ties every number back to the file and environment it came from.
    assert "## Provenance" in report
    assert "2026-01-01T00:00:00Z" in report
    assert "pyca/cryptography (OpenSSL)" in report
    # Paths outside the repo keep their own form, but never a Windows separator
    # that would render differently in the published document.
    assert "\\" not in report


def test_consolidate_omits_the_warmup_clause_for_a_legacy_results_file(tmp_path: Path) -> None:
    """A results.json written before the harness recorded `warmup` is still a
    valid file. The clause is dropped rather than filled with a zero, which
    would report a warm-up count nobody measured."""
    server = _server_fixture()
    results = server["results"]
    assert isinstance(results, list)
    for result in results:
        assert isinstance(result, dict)
        for row in result["rows"]:
            for side in ("pqc", "classical"):
                if isinstance(row.get(side), dict):
                    row[side].pop("warmup", None)

    code, out = _run(tmp_path, _write_inputs(tmp_path, server=server))
    assert code == 0
    report = out.read_text(encoding="utf-8")
    assert "Native: 10 samples per row, one call per sample (no batching needed)." in report
    assert "discarded warm-up" not in report.split("Native:")[1].split("\n")[0]


def test_consolidate_says_so_when_the_breakdown_is_absent(tmp_path: Path) -> None:
    """A `/bench b4` run has no B1/B2 to price against. The merged report says
    that outright rather than leaving a silent hole where a table was."""
    browser = _browser_fixture()
    results = browser["results"]
    assert isinstance(results, list)
    b4 = results[3]
    assert isinstance(b4, dict)
    del b4["breakdown"]
    code, out = _run(tmp_path, _write_inputs(tmp_path, browser=browser))
    assert code == 0
    report = out.read_text(encoding="utf-8")
    assert "Where the time goes" not in report
    assert "No primitive breakdown in this run" in report


def test_consolidate_refuses_a_missing_browser_json(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code, out = _run(tmp_path, _write_inputs(tmp_path, browser=None))
    assert code == 1
    assert not out.exists()  # no partial report left behind
    message = capsys.readouterr().err
    assert "Browser results not found" in message
    assert BROWSER_REMEDY in message


def test_consolidate_refuses_a_partial_browser_run(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code, out = _run(tmp_path, _write_inputs(tmp_path, browser=_browser_fixture(("B1", "B2"))))
    assert code == 1
    assert not out.exists()
    message = capsys.readouterr().err
    assert "missing B3, B4" in message  # names exactly what is absent
    assert BROWSER_REMEDY in message


def test_consolidate_names_the_target_that_produces_each_missing_input(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code, _ = _run(tmp_path, _write_inputs(tmp_path, server=None))
    assert code == 1
    assert SERVER_REMEDY in capsys.readouterr().err

    code, _ = _run(tmp_path, _write_inputs(tmp_path, bundle=None))
    assert code == 1
    assert BUNDLE_REMEDY in capsys.readouterr().err


def test_consolidate_refuses_unreadable_json(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    paths = _write_inputs(tmp_path)
    paths["browser"].write_text("{ not json", encoding="utf-8")
    code, out = _run(tmp_path, paths)
    assert code == 1
    assert not out.exists()
    assert "is not valid JSON" in capsys.readouterr().err
