PYTHON ?= python3
SCORE_REPO ?= ../appsec-tools
ANALYZER_REPO ?= ../appsec-analyzer
WHEELS ?= .wheelhouse

.PHONY: release-check
release-check:
	$(PYTHON) scripts/audit_lock.py
	$(PYTHON) -m venv .venv
	.venv/bin/python -m pip download --only-binary=:all: --require-hashes -r requirements-linux-py310.lock -d $(WHEELS)
	.venv/bin/python -m pip install --no-index --find-links $(WHEELS) --require-hashes -r requirements-linux-py310.lock
	.venv/bin/python scripts/build_release.py --score $(SCORE_REPO) --analyzer $(ANALYZER_REPO)
	.venv/bin/python -m pip install --no-index --no-deps --find-links dist --require-hashes -r dist/release.lock
	.venv/bin/python -m pip check
	.venv/bin/python -m unittest discover -s tests
	.venv/bin/python tests/pipx_release.py --score $(SCORE_REPO) --wheels $(WHEELS)
