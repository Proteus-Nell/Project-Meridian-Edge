# Benchmark harness

Suites B1–B5 per MVP_DOC.md §8 (PQC vs classical baselines). Built in W6.

This is the **only** part of the repository allowed to reference classical
asymmetric primitives (X25519, Ed25519) — they are the comparison baselines.
The `scripts/audit.py` CI gate deliberately excludes this directory.
