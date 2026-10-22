PY ?= python3

# The demo report and the committed fixtures use fixed start instants so that
# two runs, on two machines, produce the same bytes. A demo that changes every
# time it is regenerated cannot be cited in a README.
DEMO_START ?= 2026-10-21T08:00:00Z
FIXTURE_START ?= 2025-10-09T08:53:20Z

.PHONY: help test demo fixtures site install clean

help:
	@echo "make test      run the full suite (stdlib unittest, no installs)"
	@echo "make demo      generate synthetic captures and a report into demo/"
	@echo "make site      regenerate the published demo in docs/"
	@echo "make fixtures  regenerate tests/fixtures from the generator"
	@echo "make install   pip install -e ."
	@echo "make clean     remove generated output"

test:
	$(PY) -m unittest discover -s tests -v

demo:
	$(PY) -m netwatch demo --out demo --start $(DEMO_START)

site:
	$(PY) -m netwatch demo --out docs --start $(DEMO_START)
	@echo "docs/ is ready to publish; open docs/index.html or serve it with: $(PY) -m http.server -d docs"

fixtures:
	rm -rf build/fixtures
	$(PY) -m netwatch demo --out build/fixtures --start $(FIXTURE_START) >/dev/null
	cp build/fixtures/captures/*.pcap tests/fixtures/
	cp build/fixtures/baseline.json tests/fixtures/
	@echo "fixtures regenerated; run 'make test' to confirm nothing drifted"

install:
	$(PY) -m pip install -e .

clean:
	rm -rf demo build *.egg-info .pytest_cache
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
