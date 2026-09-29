# Fuzzing kit

`testing.F` targets live next to the code they exercise, behind
`//go:build fuzz`, so `go build ./...` and `go test ./...` never see them. List
them with `make -C fuzz list`.

## Tiny tier (native, no tooling)

    make -C fuzz quick FUZZ=./core/pki/ FUZZFUNC=FuzzParseDocument FUZZTIME=30s

## Big tier (libFuzzer, autoscaling)

Needs `clang` and `go-118-fuzz-build` (the Makefile installs the tool on
demand). Fork mode runs one worker per core, so the same command fills a
2-core box or a 200-core box.

    make -C fuzz build FUZZ=./core/wire/commands/ FUZZFUNC=FuzzMixnetCommandsFromBytes
    make -C fuzz run   FUZZ=./core/wire/commands/ FUZZFUNC=FuzzMixnetCommandsFromBytes

## Overnight

    make -C fuzz overnight FUZZ=./core/wire/commands/ FUZZFUNC=FuzzMixnetCommandsFromBytes

Runs `OVERNIGHT` seconds (default 8h) across every core, keeps going past
crashes, and logs to `fuzz/bin/<FuzzName>.log`. Add `IDLE=2` to leave two cores
free (`IDLE=<n>` leaves n). Crashers land in
`fuzz/bin/crash-*`; replay one with `fuzz/bin/<FuzzName> fuzz/bin/crash-<hash>`.
New corpus is written back to `fuzz/corpus/<FuzzName>/`.

## Everything, overnight, gentle on a laptop

    make -C fuzz laptop

Runs every target in the native engine, sharing `OVERNIGHT` (default 8h) across
them, niced and leaving two cores free. Native crashers land in the package's
`testdata/fuzz/<FuzzName>/`, and per-target execs and elapsed are appended to
`fuzz/bin/overnight-all.log`. On a big box use `make -C fuzz overnight-all IDLE=0`.

Report a reproduced crash on the fuzzing-findings branch.

Layout: `Makefile`, `deps.go` (the fuzz-only tool-dep pin), `corpus/` (seeds),
git-ignored `bin/`.
