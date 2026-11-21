PYTHON ?= python3
SCORE_REPO ?= ../appsec-tools
ANALYZER_REPO ?= ../appsec-analyzer
WHEELS ?= .wheelhouse
VENV := .venv/bin/python
LOCK := requirements-linux-py310.lock

.PHONY: install release-check build

# Build this checkout and install it with pipx, without a package index.
install: build
	PIP_NO_INDEX=1 PIP_FIND_LINKS="$(CURDIR)/dist $(CURDIR)/$(WHEELS)" \
		pipx install --force --pip-args=--force-reinstall appsec-cli
	@echo "Installed. Run: appsec-cli"

# Check a release before you publish it: audit, versions, contract and pipx tests.
release-check:
	$(PYTHON) scripts/audit_lock.py
	$(MAKE) build RELEASE=--release
	$(VENV) -m pip install --no-index --no-deps --find-links dist --require-hashes -r dist/release.lock
	$(VENV) -m pip check
	$(VENV) -m unittest discover -s tests
	$(VENV) tests/pipx_release.py --score $(SCORE_REPO) --wheels $(WHEELS)

# Build the wheels of the suite and its engines in dist/.
build:
	$(PYTHON) -m venv .venv
	$(VENV) -m pip download -q --only-binary=:all: --require-hashes -r $(LOCK) -d $(WHEELS)
	$(VENV) -m pip install -q --no-index --find-links $(WHEELS) --require-hashes -r $(LOCK)
	rm -rf dist
	$(VENV) scripts/build_release.py $(RELEASE) --score $(SCORE_REPO) --analyzer $(ANALYZER_REPO)
