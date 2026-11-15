# One PyPI stellar-sdk version directory (drivers/python/<version>/Makefile includes this file). It meets the
# driver directory contract in drivers/README.md:
#   fetch  (network allowed) download every wheel requirements.txt pins, and the test tools that
#          scripts/py/requirements.txt pins, into $(XDRCHECK_CACHE_DIR)/wheels; pip checks each wheel's sha256
#   build  (offline) create the venv $(XDRCHECK_CACHE_DIR)/venv with the pinned CPython, install requirements.txt
#          into it from the wheelhouse alone (--no-index --require-hashes), then write bin/xdrcheck-driver, which
#          runs the shared driver source in ../src/ with that venv's interpreter in isolated mode (-I)
#   test   (offline) the shared driver tests (../test/run.py) for this version, after build, run by a second
#          venv holding only the test tools
#   clean  remove bin/ and the two venvs
#
# Built from an SDK checkout (xdrcheck conform fetch|build --sdk PATH sets XDRCHECK_SDK_SOURCE, in a private copy of
# drivers/python): fetch also builds a wheel of the checkout (pip wheel --no-deps, its own build backend fetched
# from the index) into $(XDRCHECK_CACHE_DIR)/source-wheel; build installs requirements.txt without its stellar-sdk
# line (still hash-checked), then the checkout's wheel without dependencies, runs pip check (the checkout must
# work with the pinned dependencies), accepts the checkout's own version in the describe check and writes
# bin/xdrcheck-sdk-source naming the checkout. The rules refuse a checkout build in a directory inside the repository.
SHELL := bash
.SHELLFLAGS := -euo pipefail -c

VERSION := $(notdir $(CURDIR))
PYDIR := $(abspath $(CURDIR)/..)
XDRCHECK_ROOT ?= $(abspath $(CURDIR)/../../..)
XDRCHECK_CACHE_DIR ?= $(firstword $(wildcard $(HOME)/.cache/xdrcheck) $(wildcard $(HOME)/.cache/xcc) $(HOME)/.cache/xdrcheck)/conform/drivers-python-$(VERSION)
XDRCHECK_SDK_SOURCE ?=
WHEELS := $(XDRCHECK_CACHE_DIR)/wheels
VENV := $(XDRCHECK_CACHE_DIR)/venv
TESTVENV := $(XDRCHECK_CACHE_DIR)/test-venv
STAMP := $(XDRCHECK_CACHE_DIR)/fetched
TEST_REQS := $(XDRCHECK_ROOT)/scripts/py/requirements.txt
SOURCE_WHEEL := $(XDRCHECK_CACHE_DIR)/source-wheel
DEP_REQS := $(XDRCHECK_CACHE_DIR)/requirements-without-sdk.txt

# The interpreter the venvs are made from: the toolchain's CPython, which must be the pinned version.
PYTHON ?= python3
# pip in isolated mode: no user configuration, no PIP_* environment, never an index unless fetch names one.
PIP_FLAGS := --isolated --disable-pip-version-check --no-input --only-binary=:all: --require-hashes
PIP_OFFLINE := $(PIP_FLAGS) --no-index --no-cache-dir --find-links $(WHEELS)
LOCKS = sha256sum requirements.txt $(TEST_REQS) | cut -d' ' -f1 | tr '\n' ' '

.PHONY: fetch build test clean check-python source-guard

check-python:
	@want=$$($(PYTHON) -I -c "import tomllib; print(tomllib.load(open('$(XDRCHECK_ROOT)/pins.toml', 'rb'))['python']['version'])"); \
	  have=$$($(PYTHON) -I -c "import platform; print(platform.python_version())"); \
	  test "$$have" = "$$want" || { echo "python $(VERSION): $(PYTHON) is CPython $$have, pins.toml wants $$want" >&2; exit 1; }

# A checkout build runs only in the copy xdrcheck conform makes, never in the repository itself.
source-guard:
	@if [ -n "$(XDRCHECK_SDK_SOURCE)" ]; then \
	  case "$(CURDIR)/" in "$(abspath $(XDRCHECK_ROOT))/"*) \
	    echo "python $(VERSION): XDRCHECK_SDK_SOURCE builds only in a copy of the driver directory (xdrcheck conform fetch --sdk makes one), never in $(CURDIR)" >&2; exit 1;; esac; \
	  test -f "$(XDRCHECK_SDK_SOURCE)/pyproject.toml" || { echo "python $(VERSION): $(XDRCHECK_SDK_SOURCE) has no pyproject.toml" >&2; exit 1; }; \
	fi

fetch: check-python source-guard
	mkdir -p $(WHEELS)
	$(PYTHON) -I -m pip download $(PIP_FLAGS) --no-deps --cache-dir $(XDRCHECK_CACHE_DIR)/pip-cache --dest $(WHEELS) -r requirements.txt
	$(PYTHON) -I -m pip download $(PIP_FLAGS) --no-deps --cache-dir $(XDRCHECK_CACHE_DIR)/pip-cache --dest $(WHEELS) -r $(TEST_REQS)
	rm -rf $(SOURCE_WHEEL)
	if [ -n "$(XDRCHECK_SDK_SOURCE)" ]; then \
	  mkdir -p $(XDRCHECK_CACHE_DIR)/tmp; \
	  TMPDIR=$(XDRCHECK_CACHE_DIR)/tmp $(PYTHON) -I -m pip wheel --isolated --disable-pip-version-check --no-input --no-deps \
	    --cache-dir $(XDRCHECK_CACHE_DIR)/pip-cache --wheel-dir $(SOURCE_WHEEL) "$(XDRCHECK_SDK_SOURCE)"; \
	  echo "$(XDRCHECK_SDK_SOURCE)" > $(SOURCE_WHEEL)/source; \
	fi
	$(LOCKS) > $(STAMP)

build: check-python source-guard
	@test -z "$${XDRCHECK_SDK_VERSION:-}" || test "$$XDRCHECK_SDK_VERSION" = "$(VERSION)" || { echo "python $(VERSION): XDRCHECK_SDK_VERSION is $$XDRCHECK_SDK_VERSION" >&2; exit 1; }
	@test -f $(STAMP) || { echo "python $(VERSION): $(XDRCHECK_CACHE_DIR) is empty; run xdrcheck conform fetch (or make fetch) first" >&2; exit 1; }
	@test "$$(cat $(STAMP))" = "$$($(LOCKS))" || { echo "python $(VERSION): the cache was filled from other requirements files; fetch again" >&2; exit 1; }
	@test -z "$(XDRCHECK_SDK_SOURCE)" || test "$$(cat $(SOURCE_WHEEL)/source 2>/dev/null)" = "$(XDRCHECK_SDK_SOURCE)" \
	  || { echo "python $(VERSION): $(SOURCE_WHEEL) holds no wheel of $(XDRCHECK_SDK_SOURCE); run xdrcheck conform fetch --sdk (or make fetch) first" >&2; exit 1; }
	rm -f bin/xdrcheck-sdk-source
	rm -rf $(VENV)
	$(PYTHON) -I -m venv $(VENV)
	if [ -z "$(XDRCHECK_SDK_SOURCE)" ]; then \
	  $(VENV)/bin/python -I -m pip install $(PIP_OFFLINE) --report $(VENV)/xdrcheck-install-report.json --quiet -r requirements.txt; \
	else \
	  grep -v '^stellar-sdk==' requirements.txt > $(DEP_REQS); \
	  $(VENV)/bin/python -I -m pip install $(PIP_OFFLINE) --report $(VENV)/xdrcheck-install-report.json --quiet -r $(DEP_REQS); \
	  $(VENV)/bin/python -I -m pip install --isolated --disable-pip-version-check --no-input --no-index --no-cache-dir \
	    --no-deps --quiet $(SOURCE_WHEEL)/*.whl; \
	fi
	$(VENV)/bin/python -I -m pip check --isolated --disable-pip-version-check \
	  || { echo "python $(VERSION): the installed packages do not fit together (above)$(if $(XDRCHECK_SDK_SOURCE),: the checkout $(XDRCHECK_SDK_SOURCE) needs other dependency versions than requirements.txt pins)" >&2; exit 1; }
	mkdir -p bin
	sed -e "s|@PYTHON@|$(VENV)/bin/python|" -e "s|@PYCACHE@|$(XDRCHECK_CACHE_DIR)/pycache|" $(PYDIR)/src/xdrcheck-driver.in > bin/xdrcheck-driver.tmp
	chmod +x bin/xdrcheck-driver.tmp
	mv bin/xdrcheck-driver.tmp bin/xdrcheck-driver
	want=$(VERSION); \
	if [ -n "$(XDRCHECK_SDK_SOURCE)" ]; then \
	  want=$$($(VENV)/bin/python -I -c "from importlib.metadata import version; print(version('stellar-sdk'))"); \
	fi; \
	out=$$(printf '%s\n' '{"xcc":"xcc.driver/1","id":1,"op":"describe"}' '{"xcc":"xcc.driver/1","id":2,"op":"shutdown"}' \
	  | bin/xdrcheck-driver); [[ "$$out" == *"\"package\":\"stellar-sdk\",\"version\":\"$$want\""* ]] \
	  || { echo "python $(VERSION): the built driver does not describe stellar-sdk $$want: $$out" >&2; exit 1; }
	if [ -n "$(XDRCHECK_SDK_SOURCE)" ]; then echo "$(XDRCHECK_SDK_SOURCE)" > bin/xdrcheck-sdk-source; fi

$(TESTVENV)/stamp: $(TEST_REQS) $(STAMP)
	rm -rf $(TESTVENV)
	$(PYTHON) -I -m venv $(TESTVENV)
	$(TESTVENV)/bin/python -I -m pip install $(PIP_OFFLINE) --quiet -r $(TEST_REQS)
	touch $@

test: build $(TESTVENV)/stamp
	@test -x bin/xdrcheck-driver || { echo "python $(VERSION): bin/xdrcheck-driver is missing; run make build first" >&2; exit 1; }
	$(TESTVENV)/bin/python -I -X pycache_prefix=$(XDRCHECK_CACHE_DIR)/pycache $(PYDIR)/test/run.py --driver bin/xdrcheck-driver --version $(VERSION) --root $(XDRCHECK_ROOT)

clean:
	rm -rf bin $(VENV) $(TESTVENV)
