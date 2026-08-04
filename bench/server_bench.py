#!/usr/bin/env python3
"""Server-side benchmark harness (suites B1/B2 native column).

PQC vs classical primitive latency, measured with pyca `cryptography` for BOTH
sides - ML-KEM-768 / ML-DSA-65 and X25519 / Ed25519 share one OpenSSL 3.5
backend, so this is an apples-to-apples "same library, same backend"
comparison. (The original spec named liboqs-python for the PQC side; since
`cryptography` 49 exposes ML-KEM/ML-DSA natively and is already a pinned
runtime dependency, using it avoids a heavyweight extra dependency and removes
the library variable from the measurement.)

This directory is the ONLY place classical asymmetric primitives are allowed
(scripts/audit.py excludes it) - here they are the comparison baseline.

Run:  python bench/server_bench.py           # human-readable tables to stdout
      python bench/server_bench.py --json     # machine-readable JSON to stdout
      make bench                               # writes bench/out/{report.md,results.json}
"""

from __future__ import annotations

import argparse
import json
import platform
import statistics
import sys
import time
from collections.abc import Callable
from dataclasses import asdict, dataclass
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ed25519, mldsa, mlkem, x25519

WARMUP = 100
ITERS = 1000
MESSAGE = b"Meridian Edge benchmark fixed message"


@dataclass(frozen=True)
class Stats:
    label: str
    iters: int
    median_us: float
    p95_us: float
    mean_us: float
    min_us: float
    ops_per_sec: float


def summarize(label: str, samples_us: list[float]) -> Stats:
    """Reduce per-op microsecond samples to summary statistics. Pure."""
    if not samples_us:
        return Stats(label, 0, 0.0, 0.0, 0.0, 0.0, 0.0)
    ordered = sorted(samples_us)
    n = len(ordered)
    median = statistics.median(ordered)
    p95 = ordered[min(n - 1, max(0, (95 * n + 99) // 100 - 1))]
    mean = statistics.fmean(ordered)
    return Stats(
        label=label,
        iters=n,
        median_us=median,
        p95_us=p95,
        mean_us=mean,
        min_us=ordered[0],
        ops_per_sec=(1_000_000 / mean) if mean > 0 else 0.0,
    )


def timeit(label: str, fn: Callable[[], object], *, warmup: int = WARMUP, iters: int = ITERS) -> Stats:
    """Time `fn` per the methodology (warm-up discarded, median/p95 of iters).
    perf_counter has sub-microsecond resolution, so per-call timing is fine
    without batching (unlike the browser's clamped timer)."""
    for _ in range(warmup):
        fn()
    samples: list[float] = []
    for _ in range(iters):
        start = time.perf_counter()
        fn()
        samples.append((time.perf_counter() - start) * 1_000_000)
    return summarize(label, samples)


@dataclass(frozen=True)
class LatencyRow:
    op: str
    pqc: Stats
    #: None when the classical side has no operation of its own to time and its
    #: baseline is reported once on a different row (B1 decaps - see the
    #: result's note). Rendered as "-" rather than repeating the other row's
    #: number, which would read as a second measurement.
    classical: Stats | None = None


@dataclass(frozen=True)
class LatencyResult:
    suite: str
    title: str
    pqc_name: str
    classical_name: str
    rows: list[LatencyRow]
    note: str | None = None


@dataclass(frozen=True)
class FootprintResult:
    suite: str
    title: str
    sessions: int
    total_bytes: int
    bytes_per_session: float
    note: str


def bench_b5_memory(sessions: int) -> FootprintResult:
    """B5 - server footprint per active session. Measures the Python-heap
    allocation (tracemalloc) for the real per-session server object - a
    SessionToken ORM instance plus its SHA-512 token hash - across `sessions`
    sessions. Excludes the DB engine and native/OpenSSL allocations, which
    tracemalloc does not see; it is a per-session Python-heap figure, not full
    RSS (psutil/resource are not portable and unavailable here)."""
    import gc
    import tracemalloc

    server_dir = Path(__file__).resolve().parent.parent / "server"
    if str(server_dir) not in sys.path:
        sys.path.insert(0, str(server_dir))
    from app.models import SessionToken  # type: ignore[import-not-found]
    from app.security import hash_token, new_session_token  # type: ignore[import-not-found]

    gc.collect()
    tracemalloc.start()
    base = tracemalloc.get_traced_memory()[0]
    held: list[SessionToken] = []
    for i in range(sessions):
        token = new_session_token()
        held.append(
            SessionToken(token_hash=hash_token(token), user_id=i, last_used=0.0, revoked=False)
        )
    used = tracemalloc.get_traced_memory()[0] - base
    tracemalloc.stop()
    assert len(held) == sessions  # keep `held` alive across the measurement
    return FootprintResult(
        suite="B5",
        title="B5 - server footprint (per active session)",
        sessions=sessions,
        total_bytes=used,
        bytes_per_session=used / sessions if sessions else 0.0,
        note="Python-heap (tracemalloc) for the SessionToken object + hashed token; excludes DB engine and native/OpenSSL memory.",
    )


NOTE_B1 = (
    "X25519 has no split encaps/decaps. The single exchange() measurement shown on the encaps "
    "row is the classical baseline for both ML-KEM encaps and decaps; the decaps row leaves its "
    "classical cells blank rather than repeat that one number as if it were two."
)


def bench_b1(iters: int) -> LatencyResult:
    """B1 - KEM latency: ML-KEM-768 vs X25519.

    DH has no split encaps/decaps, so the X25519 shared-secret derivation is the
    closest analog to both ML-KEM halves. It is timed once and reported on the
    encaps row; the decaps row carries no classical cell at all, so the one
    measurement can never be mistaken for two (NOTE_B1)."""
    kem_sk = mlkem.MLKEM768PrivateKey.generate()
    kem_pk = kem_sk.public_key()
    _, kem_ct = kem_pk.encapsulate()
    x_sk = x25519.X25519PrivateKey.generate()
    x_peer = x25519.X25519PrivateKey.generate().public_key()

    kem_keygen = timeit("ml-kem keygen", mlkem.MLKEM768PrivateKey.generate, iters=iters)
    x_keygen = timeit("x25519 keygen", x25519.X25519PrivateKey.generate, iters=iters)
    kem_encaps = timeit("ml-kem encaps", kem_pk.encapsulate, iters=iters)
    x_derive = timeit("x25519 derive", lambda: x_sk.exchange(x_peer), iters=iters)
    kem_decaps = timeit("ml-kem decaps", lambda: kem_sk.decapsulate(kem_ct), iters=iters)

    rows = [
        LatencyRow("keygen", kem_keygen, x_keygen),
        LatencyRow("encaps", kem_encaps, x_derive),
        LatencyRow("decaps", kem_decaps),  # baseline is the encaps row's figure
    ]
    return LatencyResult(
        "B1", "B1 - KEM primitive latency", "ML-KEM-768", "X25519", rows, NOTE_B1
    )


def bench_b2(iters: int) -> LatencyResult:
    """B2 - signature latency: ML-DSA-65 vs Ed25519."""
    dsa_sk = mldsa.MLDSA65PrivateKey.generate()
    dsa_pk = dsa_sk.public_key()
    dsa_sig = dsa_sk.sign(MESSAGE)
    ed_sk = ed25519.Ed25519PrivateKey.generate()
    ed_pk = ed_sk.public_key()
    ed_sig = ed_sk.sign(MESSAGE)

    rows = [
        LatencyRow(
            "keygen",
            timeit("ml-dsa keygen", mldsa.MLDSA65PrivateKey.generate, iters=iters),
            timeit("ed25519 keygen", ed25519.Ed25519PrivateKey.generate, iters=iters),
        ),
        LatencyRow(
            "sign",
            timeit("ml-dsa sign", lambda: dsa_sk.sign(MESSAGE), iters=iters),
            timeit("ed25519 sign", lambda: ed_sk.sign(MESSAGE), iters=iters),
        ),
        LatencyRow(
            "verify",
            timeit("ml-dsa verify", lambda: dsa_pk.verify(dsa_sig, MESSAGE), iters=iters),
            timeit("ed25519 verify", lambda: ed_pk.verify(ed_sig, MESSAGE), iters=iters),
        ),
    ]
    return LatencyResult("B2", "B2 - signature primitive latency", "ML-DSA-65", "Ed25519", rows)


def _fmt_us(us: float) -> str:
    if us == 0:
        return "-"
    if us >= 1000:
        return f"{us / 1000:.3f} ms"
    return f"{us:.2f} us"


def _factor(pqc: float, classical: float) -> str:
    if classical <= 0:
        return "-"
    f = pqc / classical
    return f"x{round(f)}" if f >= 10 else f"x{f:.1f}"


def _classical_cells(row: LatencyRow) -> tuple[str, str, str]:
    """The classical median / p95 / factor cells, or three blanks when the row
    has no classical measurement of its own (see LatencyResult.note)."""
    if row.classical is None:
        return ("-", "-", "-")
    return (
        _fmt_us(row.classical.median_us),
        _fmt_us(row.classical.p95_us),
        _factor(row.pqc.median_us, row.classical.median_us),
    )


def render_terminal(results: list[LatencyResult], footprint: FootprintResult | None = None) -> str:
    lines: list[str] = [f"Environment: {platform.python_implementation()} {platform.python_version()} on {platform.platform()}"]
    for r in results:
        lines.append("")
        lines.append(f"{r.title}  ({r.pqc_name} PQC vs {r.classical_name} classical, median of {r.rows[0].pqc.iters})")
        header = f"  {'op':<8} {r.pqc_name + ' med':>16} {'p95':>12} {r.classical_name + ' med':>14} {'p95':>12} {'factor':>7}"
        lines.append(header)
        lines.append("  " + "-" * (len(header) - 2))
        for row in r.rows:
            classical_med, classical_p95, factor = _classical_cells(row)
            lines.append(
                f"  {row.op:<8} {_fmt_us(row.pqc.median_us):>16} {_fmt_us(row.pqc.p95_us):>12} "
                f"{classical_med:>14} {classical_p95:>12} {factor:>7}"
            )
        if r.note is not None:
            lines.append(f"  note: {r.note}")
    if footprint is not None:
        lines.append("")
        lines.append(f"{footprint.title}  ({footprint.sessions} sessions)")
        lines.append(f"  {footprint.bytes_per_session:,.0f} bytes/session ({footprint.total_bytes:,} total)")
        lines.append(f"  note: {footprint.note}")
    return "\n".join(lines)


def render_markdown(results: list[LatencyResult], footprint: FootprintResult | None = None) -> str:
    parts = [
        "# Meridian Edge server benchmark",
        "",
        f"Environment: {platform.python_implementation()} {platform.python_version()}, "
        f"{platform.platform()}. pyca/cryptography (OpenSSL) for both PQC and classical.",
    ]
    for r in results:
        parts += ["", f"## {r.title}", "", f"{r.pqc_name} (PQC) vs {r.classical_name} (classical), median / p95 over {r.rows[0].pqc.iters} iterations.", ""]
        parts.append(f"| op | {r.pqc_name} median | {r.pqc_name} p95 | {r.classical_name} median | {r.classical_name} p95 | factor |")
        parts.append("| --- | --- | --- | --- | --- | --- |")
        for row in r.rows:
            classical_med, classical_p95, factor = _classical_cells(row)
            parts.append(
                f"| {row.op} | {_fmt_us(row.pqc.median_us)} | {_fmt_us(row.pqc.p95_us)} | "
                f"{classical_med} | {classical_p95} | {factor} |"
            )
        if r.note is not None:
            parts += ["", f"_{r.note}_"]
    if footprint is not None:
        parts += [
            "",
            f"## {footprint.title}",
            "",
            f"| sessions | bytes/session | total |",
            "| --- | --- | --- |",
            f"| {footprint.sessions} | {footprint.bytes_per_session:,.0f} | {footprint.total_bytes:,} |",
            "",
            f"_{footprint.note}_",
        ]
    return "\n".join(parts) + "\n"


def _to_json(results: list[LatencyResult], footprint: FootprintResult | None = None) -> str:
    payload: dict[str, object] = {
        "environment": {
            "python": platform.python_version(),
            "implementation": platform.python_implementation(),
            "platform": platform.platform(),
            "library": "pyca/cryptography (OpenSSL)",
        },
        "results": [
            {
                "suite": r.suite,
                "title": r.title,
                "pqc_name": r.pqc_name,
                "classical_name": r.classical_name,
                "note": r.note,
                # An explicit null says "not measured on this row" (the baseline
                # lives on another one); repeating the figure would claim a
                # second sample that was never taken.
                "rows": [
                    {
                        "op": row.op,
                        "pqc": asdict(row.pqc),
                        "classical": asdict(row.classical) if row.classical is not None else None,
                    }
                    for row in r.rows
                ],
            }
            for r in results
        ],
    }
    if footprint is not None:
        payload["footprint"] = asdict(footprint)
    return json.dumps(payload, indent=2)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Meridian Edge server benchmark (B1/B2)")
    parser.add_argument("--json", action="store_true", help="emit JSON instead of tables")
    parser.add_argument("--iters", type=int, default=ITERS, help="iterations per op")
    parser.add_argument("--sessions", type=int, default=1000, help="sessions for the B5 footprint")
    parser.add_argument("--out", type=Path, default=None, help="write report.md + results.json here")
    args = parser.parse_args(argv)

    results = [bench_b1(args.iters), bench_b2(args.iters)]
    footprint = bench_b5_memory(args.sessions)

    if args.out is not None:
        args.out.mkdir(parents=True, exist_ok=True)
        (args.out / "report.md").write_text(render_markdown(results, footprint), encoding="utf-8")
        (args.out / "results.json").write_text(_to_json(results, footprint), encoding="utf-8")
        print(f"wrote {args.out / 'report.md'} and {args.out / 'results.json'}")
    elif args.json:
        print(_to_json(results, footprint))
    else:
        print(render_terminal(results, footprint))
    return 0


if __name__ == "__main__":
    sys.exit(main())
