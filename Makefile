PYTHON ?= python3
# Each tool names the Git source of its engine. ENGINE_SOURCES builds engines from
# another Git URL or a local checkout instead, as space-separated PACKAGE=URL
# pairs; the build still checks out the commit pinned in the tool's directory.
ENGINE_SOURCES ?=
SOURCE_ARGS := $(foreach s,$(ENGINE_SOURCES),--source $(s))
WHEELS ?= .wheelhouse
VENV := .venv/bin/python
LOCK := requirements-linux-py310.lock
INSTALL = $(PYTHON) scripts/install.py --lock $(LOCK) --wheels $(WHEELS) $(SOURCE_ARGS)

.PHONY: install release-check build

# Build this checkout and install it with pipx, without a package index. Shows one
# line per step and writes the output to build/install.log; VERBOSE=1 shows it.
install:
	@$(INSTALL) $(if $(VERBOSE),--verbose)

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

# Build the wheels of the suite and its engines in dist/, showing every command.
build:
	@$(INSTALL) --no-install --verbose $(RELEASE)
