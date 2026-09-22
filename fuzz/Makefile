# SPDX-License-Identifier: AGPL-3.0-only

FUZZ      ?= ./core/pki/
FUZZFUNC  ?= FuzzParseDocument
FUZZTIME  ?= 30s
OVERNIGHT ?= 28800
SAN       ?=

comma := ,

NPROC   := $(shell nproc)
IDLE    ?= 0
WORKERS := $(shell w=$$(( $(NPROC) - $(IDLE) )); [ $$w -lt 1 ] && w=1; echo $$w)
MODROOT := $(abspath $(CURDIR)/..)
GOBIN   := $(shell go env GOPATH)/bin
TOOL    := $(GOBIN)/go-118-fuzz-build

BINDIR    := $(CURDIR)/bin
ARCHIVE   := $(BINDIR)/$(FUZZFUNC).a
BINARY    := $(BINDIR)/$(FUZZFUNC)
CORPUSDIR := $(CURDIR)/corpus/$(FUZZFUNC)

# go test builds and execs test binaries under GOTMPDIR; a noexec /tmp (e.g.
# on power9) makes that fail with "fork/exec ...: permission denied". Keep the
# temp dir on an exec-mounted path under bin/. Override with GOTMPDIR=<path>.
export GOTMPDIR ?= $(BINDIR)/gotmp
$(shell mkdir -p $(GOTMPDIR))

.PHONY: help list tool seed build run overnight overnight-all laptop quick clean

help:
	@echo "Override with FUZZ=<pkg> FUZZFUNC=<FuzzName>. Targets:"
	@echo "  list       list every fuzz target"
	@echo "  quick      native go test -fuzz for FUZZTIME=$(FUZZTIME)"
	@echo "  build      build the libFuzzer binary (go-118-fuzz-build + clang)"
	@echo "  run        libFuzzer fork mode, $(WORKERS) workers (IDLE=$(IDLE) of $(NPROC) cores free)"
	@echo "  overnight  one target, libFuzzer, OVERNIGHT=$(OVERNIGHT)s on $(WORKERS) workers"
	@echo "  overnight-all  every target, native, sharing OVERNIGHT across them"
	@echo "  laptop     overnight-all, niced, IDLE=2 (gentle: leaves 2 cores free)"
	@echo "  clean      remove built binaries"
	@echo "IDLE=<n> leaves n cores free (default 0); e.g. IDLE=2 keeps 2 cores idle."
	@echo "SAN=<check> links build/run/overnight with -fsanitize=fuzzer,<check> (e.g. SAN=address for cgo under ASan)."

list:
	cd $(MODROOT) && go test -tags=fuzz -list '^Fuzz' ./...

tool:
	@command -v $(TOOL) >/dev/null 2>&1 || go install github.com/AdamKorcz/go-118-fuzz-build@latest
	@test -x $(TOOL) || { echo "ERROR: $(TOOL) missing; is $(GOBIN) writable?"; exit 1; }

seed:
	@mkdir -p $(CORPUSDIR)
	cd $(MODROOT) && FUZZ_EXPORT_DIR=$(CORPUSDIR) go test -tags=fuzz -run '^$(FUZZFUNC)$$' $(FUZZ)
	@[ -n "$$(ls -A $(CORPUSDIR) 2>/dev/null)" ] || head -c 512 /dev/zero > $(CORPUSDIR)/seed-zeros

build: tool seed
	@command -v clang >/dev/null 2>&1 || { echo "ERROR: clang not found"; exit 1; }
	@mkdir -p $(BINDIR)
	cd $(MODROOT) && GOFLAGS=-mod=mod $(TOOL) -tags fuzz -o $(ARCHIVE) -func $(FUZZFUNC) $(FUZZ) || { \
		echo "go-118-fuzz-build failed; recover with: git -C $(MODROOT) checkout -- $(FUZZ) && rm -f $(MODROOT)/$(FUZZ)/*_fuzz.go $(MODROOT)/main.*.go"; exit 1; }
	clang -fsanitize=fuzzer$(if $(SAN),$(comma)$(SAN)) $(ARCHIVE) -o $(BINARY) -lpthread -lm
	@echo "built $(BINARY)"

run: build
	cd $(BINDIR) && ./$(FUZZFUNC) -fork=1 -jobs=$(WORKERS) -workers=$(WORKERS) $(CORPUSDIR)

overnight: build
	cd $(BINDIR) && ./$(FUZZFUNC) -fork=1 -jobs=$(WORKERS) -workers=$(WORKERS) -ignore_crashes=1 \
		-max_total_time=$(OVERNIGHT) -print_final_stats=1 -artifact_prefix=$(BINDIR)/ $(CORPUSDIR) \
		2>&1 | tee $(BINDIR)/$(FUZZFUNC).log

overnight-all:
	@cd $(MODROOT); \
	files=$$(grep -rlE 'func Fuzz[A-Za-z0-9_]+\([a-zA-Z0-9_ ]*\*testing\.F\)' --include='*_test.go' --exclude-dir=docker --exclude-dir=vendor --exclude-dir=.git . 2>/dev/null); \
	pairs=""; for f in $$files; do d=$$(dirname $$f); \
		for fn in $$(grep -oE 'func Fuzz[A-Za-z0-9_]+\(' $$f | sed -E 's/func (Fuzz[A-Za-z0-9_]+)\(/\1/'); do \
			pairs="$$pairs $$d:$$fn"; done; done; \
	n=$$(echo $$pairs | wc -w); [ $$n -gt 0 ] || { echo "no fuzz targets"; exit 1; }; \
	per=$$(( $(OVERNIGHT) / n )); [ $$per -lt 30 ] && per=30; \
	mkdir -p $(BINDIR); log=$(BINDIR)/overnight-all.log; \
	echo "# $$n targets, $${per}s each, $(WORKERS) of $(NPROC) cores (IDLE=$(IDLE))" | tee -a $$log; \
	for p in $$pairs; do pkg=$${p%%:*}; fn=$${p##*:}; \
		echo "=== $$fn  $$pkg ==="; \
		out=$$(GOMAXPROCS=$(WORKERS) go test -tags=fuzz -run '^$$' -fuzz="^$${fn}$$" -fuzztime=$${per}s $$pkg 2>&1 || true); \
		echo "$$out"; \
		stat=$$(echo "$$out" | grep -aoE 'elapsed: [0-9hms]+, execs: [0-9]+ \([0-9]+/sec\)' | tail -1); \
		res=ok; echo "$$out" | grep -aqE 'FAIL|panic' && res=CRASH; \
		printf '%-42s %-24s %s [%s]\n' "$$fn" "$$pkg" "$${stat:-no-stat}" "$$res" >> $$log; \
	done; \
	echo "# per-target effort logged to $$log"

laptop:
	nice -n 19 $(MAKE) overnight-all IDLE=2

quick:
	cd $(MODROOT) && go test -tags=fuzz -run '^$$' -fuzz='$(FUZZFUNC)$$' -fuzztime=$(FUZZTIME) $(FUZZ)

clean:
	rm -rf $(BINDIR)
