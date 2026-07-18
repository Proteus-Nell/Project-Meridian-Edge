# Meridian Edge benchmark entry point (MVP_DOC.md §8).
#
# The server-side suites (B1/B2 latency + B5 footprint) run here; the browser
# suites (B1-B4) run interactively via `/bench` in the client terminal (they
# need the JS engine and @noble libraries). B5's bundle measurement runs here
# via Node + Vite.

PYTHON ?= python
NODE ?= node

.PHONY: bench bench-server bench-bundle bench-print bench-test

# Server B1/B2 tables + B5 footprint to bench/out/, plus the B5 bundle sizes.
bench: bench-server bench-bundle

bench-server:
	$(PYTHON) bench/server_bench.py --out bench/out

# B5 frontend bundle-size delta (PQC vs classical libs).
bench-bundle:
	$(NODE) bench/bundle_size.mjs

# Print the server tables to stdout without writing files.
bench-print:
	$(PYTHON) bench/server_bench.py

bench-test:
	cd bench && $(PYTHON) -m pytest -q
