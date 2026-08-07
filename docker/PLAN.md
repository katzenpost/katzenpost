# Plan: Thin Makefile over compose, multi-distro, parallel networks, thin_client support

### Part 1 — Makefile de-hacking (make stays thin, compose does the work)

- **1a. Collapse the genconfig flag assembly.** Replace the `ifeq`/`ifneq` flag block (lines 109–176) with one unconditional `genconfig_args`. Bools always `--noMixDecoy=$(no_mixdecoy)` etc.; tunables always `--schedulerSlack $(schedulerSlack)` (0 = library default); strings always `--kem="$(kem)"` / `--epochDuration="$(epoch_duration)"`. `sessionGracePeriod` passed as `$(or $(session_grace_period),0)` (cobra Duration rejects `""`; 0 = built-in default). `=`-expansion keeps `make mixes=10 gateways=2 start wait run-ping` working. Both genconfig invocations (line 277 and `config-only` line 292) share the one variable.
- **1b. Kill parse-time `$(shell)` detection** (lines 97, 233, 246, 250–261): `command -v podman`, `docker?=docker` override, recipe-time evaluation.
- **1c. Kill `make_args` recursion** (line 263): `export` the computed vars.
- **1d. Keep per-binary build rules** (lines 561–597) — the dev-loop feature. Use `-o $(net_name)/<name>.$(distro)` instead of `cd && mv`; keep `$(docker_run_sh)` as the single container-invocation source; keep `client-restart`/`courier-restart`/`servicenode-restart`/`replica-restart`.
- **1e. Remove the `clean` rm-in-container hack** (lines 628–629): user mapping (`--userns=keep-id`/matching `--user`) so build containers don't leave root-owned cache files.
- **1f. Derive network/container names from `$(net_name)`.** Fix hardcoded `voting_mixnet` at lines 342, 362–368, 523, 647, 671 and repo `Makefile:161`. Delete the dead `DockerProjectTag` constant (`genconfig.go:76`) — verified unused, not the cause.

### Part 2 — Multi-distro: alpine + debian (trixie/testing) + any ubuntu version, drop-in

- **2a. Two family Dockerfiles, both parameterized.**
  - `docker/Dockerfile.base.alpine` — `ARG BASE_IMAGE=docker.io/alpine:3.21`, apk installs (gcc, musl-dev, make, pv, curl, netcat-openbsd, bash, perl, coreutils, git), `adduser katzenpost`, curl-install of Go at `ARG GO_VERSION` (required build-arg, supplied by the Makefile from go.mod — see 2g).
  - `docker/Dockerfile.base.apt` — `FROM ${BASE_IMAGE}` (covers **debian-trixie, debian-testing, and every ubuntu version**), apt-get installs (build-essential/gcc, make, pv, curl, netcat-openbsd, bash, perl, coreutils, git, adduser), same `adduser` + identical curl-Go lines.
  - Only divergence between families is the package-manager line; **zero per-version code** — versions differ only in the `FROM` tag. Same GO_VERSION recipe in both (this drift is why the old debian path rotted).
- **2b. Generalize base-image rules in make.** Replace `alpine_base.stamp` / `debian_base.stamp` / `debian_base_image?` (lines 529–551) with one adaptive rule `$(distro)_base.stamp: $(base_dockerfile)` running `docker build -f $(base_dockerfile) --build-arg BASE_IMAGE=$(base_image)`. Derivation (uniform, no per-version code):
  - `distro_family = $(firstword $(subst -, ,$(distro)))` (alpine | debian | ubuntu)
  - `distro_version = $(patsubst $(distro_family)-%,%,$(distro))`
  - `base_image`: `alpine` → `alpine_base_image?=docker.io/alpine:3.21`; `debian-<tag>` → `docker.io/debian:<tag>`; `ubuntu-<tag>` → `docker.io/ubuntu:<tag>`; `base_image?=` universal override.
  - Drop-in: `make distro=debian-trixie start wait`, `distro=debian-testing …`, `distro=ubuntu-25.10 …`, `distro=ubuntu-26.04 …` (and `26.10` when released) — no new code.
  - Delete the `docker commit` recipe (lines 531–535) and `debian_base_image?`.
- **2c. `sh` grep (line 97) → `sh?=bash`** (alpine base already installs bash; debian/ubuntu ship it). Removes the last distro-conditional in make.
- **2d. `DISTROS` (line 96) = `alpine debian-trixie ubuntu-26.04`** — the supported set. `make clean`/`clean-images` scrubs every distro ever built, discovered from on-disk stamps/caches (see 6d), so dropping a version later never leaks artifacts. **`test-distros`** brings up, pings, and tears down the testnet on each entry — serially by default, in parallel with `make -j` (see 6b).
- **2e. Minor**: `check-go-version` (line 689) → `katzenpost-$(distro)_base`.
- **2f. Cache scoping (implemented)**: the go module cache (read-only source content) is shared across distros at `cache/go`, but the go **build** cache is per-distro at `cache/go-build-$(distro)` — compiled archives are sensitive to the C library (musl vs glibc, and glibc versions), which Go's cache key does not capture.
- **2g. `GO_VERSION` single source of truth**: `GO_VERSION?=$(shell grep '^go ' ../go.mod | cut -d' ' -f2)` and the base-image rule passes it as a build-arg. The base Dockerfiles declare `ARG GO_VERSION` with **no default**, so a standalone `podman build` fails fast instead of silently pinning a stale Go (the version lives only in go.mod).

### Part 3 — Fix multiple parallel networks (genconfig changes)

- **3a. Drop `container_name`** in `writeKatzenpostService` (`genconfig.go:2545–2557`) and for metrics/grafana/pyroscope (2627/2643/2669); keep `hostname: <identifier>` (selfcheck-cache matching survives) and service names = identifiers (peer DNS works per-project). Compose names containers `<project>-<svc>-1` → no collisions.
- **3b. Allocate published host ports from the `base_port` sequence** (genconfig-derived, not user-specified): published band at `base_port+2000..+2004` (kpclientd, prometheus, grafana, pyroscope, kpclientd metrics), wired into compose publishes, `client.toml`/`thinclient.toml` dial addresses, and prometheus scrape. In-bridge `kpclientd:64331` unchanged. Consequence (approved): default published ports move to 32000–32004, deliberately surfacing hardcoded ports — `genconfig_test.go`, `client/thin/thin_unit_test.go`, `CONFIG_CHANGES.md`, the kpclientd-metrics Makefile flag, and any external consumers (thin_client CI follows via the generated config). Implemented: constants next to `DockerNetwork`, `thinClientDialAddress()`/`kpclientdMetricsPort()` helpers, kpclientd-metrics port derived in `GenClient2Cfg`+`GenPrometheus`, `print-url-*` and the kpclientd-metrics flag derive from `base_port`.
- **3c. Pumba retargeting**: the default regex now anchors on the compose project prefix — `re2:^$(net_name)-(mix[0-9]+|…|kpclientd)-[0-9]+$$` — so per-project container names match and parallel networks are not disturbed; `pumba_pause_target` defaults to `$(net_name)-replica1-1`.
- **3d.** Re-verify `courier-restart`/`client-logs` (service names), selfcheck-cache-restore (hostname), watch targets (directories) under new naming.

### Part 4 — Docs

- **4a.** Rewrite `docker/README.rst`: dead targets, bridge-network layout, per-network (`net_name=`/`base_port=`), multi-distro incl. drop-in versions + `test-distros`, per-binary dev-restart, thin_client targets. (This PLAN.md replaces it as the source of truth for the redesign; README gets the user-facing usage.)

### Part 5 — thin_client / pigeonhole-cp dependency (rust)

- **5a. Pinned auto-checkout**: `make thin-client-sync` clones `github.com/katzenpost/thin_client` at `thin_client_ref?=` (tag like `0.0.23`/commit) into gitignored `docker/thin_client/` (visible to the build container via the repo mount).
- **5b. `thin_client_dir?=` override**: devs point at their own checkout; thin_client's own CI sets it to its checkout-under-test (avoids a nested clone, tests the exact code under test).
- **5c. Build in-container**: rust toolchain in a separate `Dockerfile.rust` layered on the per-distro base image (base images stay rust-free); `cargo build --release --bin pigeonhole-cp --features cli`, caches under `cache/cargo-home-$(distro)` / `cache/cargo-target-$(distro)`; the build target is the file `$(net_name)/pigeonhole-cp.$(distro)` (`.$(distro)` suffix like the go binaries).
- **5d. Scope**: only `pigeonhole-cp-*`/`thin-client-sync` targets depend on thin_client; `start`/`wait` and all existing targets stay thin_client-free (thin_client CI and katzenqt CI call `make start wait`).
- **5e. Runtime**: targets run the binary against `$(net_name)/client/thinclient.toml` (dial address carries the 3b port). Extend `tools/chaos/scripts/pigeonhole_cp_roundtrip.sh`, treating thin_client's build as the source of truth (that script currently references a different pigeonhole-cp, per your correction).
- **5f. Pin-sync table**: docker Makefile pins thin_client; cross-repo features now bump four cells in lockstep.

### Part 6 — Parallel build/test loop + exit-code-reliable run-ping

- **6a. `-j` binaries**: the per-binary rules are independent in-container build jobs sharing only concurrency-safe caches, so `make -j N testnet_binaries` is safe with no structural change (each rule already recurses via `$(MAKE)`, keeping the jobserver).
- **6b. `test-distros` parallelizable**: a phony `test-distro-<distro>` pattern target per distro; `test-distros` is their union, so it runs serially bare and in parallel under `make -j`. Each leg runs `$(MAKE) -j1 distro=$* net_name=mixnet-$* base_port=$(lookup) start wait run-ping stop` then `rm -rfv mixnet-$*`. The `-j1` forces the leg's sub-make to keep start→wait→run-ping→stop ordered even when the parent passes a jobserver (`-j start wait` would otherwise race `stop` ahead). `DISTRO_PORTS` derives each distro's `base_port` band (30000 + index-in-DISTROS × 10000) at parse time, so adding/removing a distro reflows the bands automatically.
- **6c. `run-ping` exit code**: `cmd/ping` now exits non-zero unless 100% of pings are answered — `sendPings` returns the failed count and the cobra `RunE` returns an error, which the shared fang wrapper turns into exit 1. `run-ping` also dials `/$(net_name)/client/thinclient.toml` instead of the `voting_mixnet`-pinned `client/testdata` symlink, so it works on any `net_name`; this is what makes each test-distros leg's exit code a meaningful gate.
- **6d. `clean` by discovery**: `KNOWN_DISTROS` = DISTROS ∪ (distros found in `*_{base,go_mod,rust}.stamp` and `cache/{go-build,cargo-home,cargo-target}-*`). `clean-images` loops `KNOWN_DISTROS` and removes both `_base` and `_rust` image/stamp (the `_rust` cleanup was previously dropped), then sweeps orphan containers left by an interrupted `make -j test-distros`. `clean-local` additionally removes `mixnet-*`.
- **6e. DISTROS trimmed to `alpine debian-trixie ubuntu-26.04`**; artifacts of dropped versions are still scrubbed by 6d discovery.

### Implementation order
1 → 2 (unblocks debian/ubuntu) → 3 (genconfig + test/doc updates) → 5 (needs 3b ports) → 6 (parallel/exit-code work) → 4 (last, matches reality).
