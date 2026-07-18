"""Tests for the server benchmark harness (bench/server_bench.py).

Run:  python -m pytest bench/
The pure stats are asserted exactly; the suites run with a tiny iteration
count just to prove they execute and shape their results.
"""

from __future__ import annotations

from server_bench import (  # type: ignore[import-not-found]
    bench_b1,
    bench_b2,
    bench_b5_memory,
    render_markdown,
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


def test_b1_runs_and_shapes_results() -> None:
    result = bench_b1(iters=3)
    assert result.suite == "B1"
    assert [row.op for row in result.rows] == ["keygen", "encaps", "decaps"]
    assert all(row.pqc.iters == 3 and row.classical.iters == 3 for row in result.rows)


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
