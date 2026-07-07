# PQTerm benchmark entry point (MVP_DOC.md §8).
#
# The server-side suites (B1/B2 native + B3 sizes) run here; the browser suites
# run interactively via `/bench` in the client terminal (they need the JS
# engine and @noble libraries).

PYTHON ?= python

.PHONY: bench bench-server bench-test

# Write server B1/B2 tables + JSON to bench/out/.
bench: bench-server

bench-server:
	$(PYTHON) bench/server_bench.py --out bench/out

# Print the server tables to stdout without writing files.
bench-print:
	$(PYTHON) bench/server_bench.py

bench-test:
	cd bench && $(PYTHON) -m pytest -q
