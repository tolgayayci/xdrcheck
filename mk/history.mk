# History gates (SECURITY.md): a pushed commit can never be taken back, so every commit of the range is checked,
# not only its tip. Both gates need the private overlay and fail when XDRCHECK_OVERLAY is not set: unlike
# overlay-audit, they never skip.
#
#   make push-gate RANGE=<last-pushed>..main [COMMIT_MAP=FILE]
#   make history-audit [RANGE=main]
#
# push-gate runs, at every commit of RANGE: the overlay audit (all kinds, blob-id included) and the public-tree
# scan; then the scan of every commit message; then the ref checks: only refs/heads/main is pushed and RANGE
# ends at it, and, with COMMIT_MAP (old and new ids, one pair per line, as git filter-repo writes them), no
# rewritten-away commit is reachable from main. Every check runs; the gate fails if any fails.
# history-audit runs the same scans over RANGE (default main, else HEAD) without the ref checks.
.PHONY: push-gate history-audit history-selftest

RANGE      ?=
COMMIT_MAP ?=
PUSH_REF   := main

# $(call history-scans,RANGE): the overlay audit and the public scan at every commit of RANGE, and its messages.
define history-scans
	@test -n "$${XDRCHECK_OVERLAY:-}" && test -d "$${XDRCHECK_OVERLAY}" || { echo "$@: XDRCHECK_OVERLAY must name the private overlay" >&2; exit 2; }
	@case '$(1)' in ''|-*) echo "$@: RANGE '$(1)' is not a revision range" >&2; exit 2;; esac
	@fail=0; \
	  echo "== overlay audit at every commit of $(1)"; $(XDRCHECK) overlay audit --overlay "$$XDRCHECK_OVERLAY" --revs '$(1)' || fail=1; \
	  echo "== public-tree scan at every commit of $(1)"; $(PY) scripts/py/check_public.py --revs '$(1)' || fail=1; \
	  echo "== commit messages of $(1)"; $(PY) scripts/py/check_public.py --messages '$(1)' || fail=1; \
	  exit $$fail
endef

##@ Before a push (every commit of a range; needs XDRCHECK_OVERLAY)
push-gate: tool-xdrcheck ## RANGE=<last-pushed>..main: overlay audit, public scan and message scan at every commit, then the ref checks (COMMIT_MAP=FILE adds the old-id check)
	$(call history-scans,$(RANGE))
	@tip=$$(git rev-parse --verify --quiet 'refs/heads/$(PUSH_REF)^{commit}') || { echo "$@: no branch $(PUSH_REF)" >&2; exit 1; }; \
	  last=$$(git rev-list --max-count=1 '$(RANGE)' --); \
	  test "$$last" = "$$tip" || { echo "$@: RANGE '$(RANGE)' does not end at $(PUSH_REF) ($${last:-empty} is not $$tip)" >&2; exit 1; }; \
	  echo "== refs: RANGE ends at refs/heads/$(PUSH_REF) $$tip; push only that ref (git push <remote> $(PUSH_REF)), no tags"
	@if [ -n "$(COMMIT_MAP)" ]; then \
	  test -f '$(COMMIT_MAP)' || { echo "$@: COMMIT_MAP $(COMMIT_MAP) is not a file" >&2; exit 1; }; \
	  stale=$$(comm -12 <(awk 'NF == 2 && $$1 ~ /^[0-9a-f]{40}$$/ && $$1 != $$2 { print $$1 }' '$(COMMIT_MAP)' | sort -u) \
	                    <(git rev-list 'refs/heads/$(PUSH_REF)' -- | sort -u) | wc -l); \
	  test "$$stale" -eq 0 || { echo "$@: $$stale rewritten-away commit(s) of $(COMMIT_MAP) are reachable from $(PUSH_REF)" >&2; exit 1; }; \
	  echo "== old ids: no rewritten-away commit of $(COMMIT_MAP) is reachable from $(PUSH_REF)"; \
	else echo "== old ids: no COMMIT_MAP given, not checked"; fi
	@echo "push-gate: $(RANGE) is clean"

history-audit: tool-xdrcheck ## overlay audit, public scan and message scan at every commit of RANGE (default main, else HEAD)
	$(call history-scans,$(or $(RANGE),$(if $(shell git rev-parse --verify --quiet refs/heads/main),main,HEAD)))

history-selftest: ## the history scans find a planted private name, label, message and overlay blob in a throwaway repository
	$(PY) scripts/py/test_check_public.py
	cd go && go test ./internal/overlay -run 'Revs|BlobID|RevList|EmitTokens'
