PYTHON ?= python3
# Each tool names the Git source of its engine. ENGINE_SOURCES builds engines from
# another Git URL or a local checkout instead, as space-separated PACKAGE=URL
# pairs; the build still checks out the commit pinned in the tool's directory.
ENGINE_SOURCES ?=
SOURCE_ARGS := $(foreach s,$(ENGINE_SOURCES),--source $(s))
WHEELS ?= .wheelhouse
VENV := .venv/bin/python
LOCK := requirements-linux-py310.lock

.PHONY: install release-check build

# Build this checkout and install it with pipx, without a package index.
install: build
	PIP_NO_INDEX=1 PIP_FIND_LINKS="$(CURDIR)/dist $(CURDIR)/$(WHEELS)" \
		pipx install --force --pip-args=--force-reinstall appsec-cli
	@echo "Installed. Run: appsec-cli"

# Check a release before you publish it: audit, versions, the tests of the core and
# of every tool, and the pipx tests over all tools of the release.
release-check:
	$(PYTHON) scripts/audit_lock.py
	$(MAKE) build RELEASE=--release
	$(VENV) -m pip install --no-index --no-deps --force-reinstall --find-links dist --require-hashes -r dist/release.lock
	$(VENV) -m pip check
	$(VENV) -m unittest discover -s tests
	for tests in tools/[!_]*/tests; do \
		[ ! -d "$$tests" ] || $(VENV) -m unittest discover -s "$$tests" || exit 1; \
	done
	$(VENV) tests/pipx_release.py --wheels $(WHEELS)

# Build the wheels of the suite and its engines in dist/.
build:
	$(PYTHON) -m venv .venv
	$(VENV) -m pip download -q --only-binary=:all: --require-hashes -r $(LOCK) -d $(WHEELS)
	$(VENV) -m pip install -q --no-index --find-links $(WHEELS) --require-hashes -r $(LOCK)
	rm -rf dist
	$(VENV) scripts/build_release.py $(RELEASE) $(SOURCE_ARGS)
