# Meridian Edge benchmark entry point.
#
# The server-side suites (B1/B2 latency + B5 footprint) run here; the browser
# suites (B1-B4) run interactively via `/bench` in the client terminal (they
# need the JS engine and @noble libraries). B5's bundle measurement runs here
# via Node + Vite.

PYTHON ?= python
NODE ?= node

# Browser results saved from /bench. Override to point somewhere else:
#   make bench-report BROWSER_JSON=~/Downloads/meridian-bench-all.json
BROWSER_JSON ?= bench/out/browser.json

.PHONY: bench bench-server bench-bundle bench-print bench-report bench-test

# Server B1/B2 tables + B5 footprint to bench/out/, plus the B5 bundle sizes.
bench: bench-server bench-bundle

bench-server:
	$(PYTHON) bench/server_bench.py --out bench/out

# B5 frontend bundle-size delta (PQC vs classical libs). Writes bundle.json for
# the consolidation step as well as printing the table.
bench-bundle:
	$(NODE) bench/bundle_size.mjs --out bench/out

# Every suite in one document. Needs `make bench` to have run and a browser
# results JSON from /bench; fails loudly rather than omitting a suite.
bench-report:
	$(PYTHON) bench/consolidate.py $(BROWSER_JSON) --out bench/out/consolidated.md

# Print the server tables to stdout without writing files.
bench-print:
	$(PYTHON) bench/server_bench.py

bench-test:
	cd bench && $(PYTHON) -m pytest -q
