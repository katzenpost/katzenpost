
.PHONY: all test test-unit test-replica bench-replica bench-sphinx bench-handshake test-config sphincsplus clean server dirauth genconfig ping courier echo-plugin fetch genkeypair geometry http-proxy-client http-proxy-server kpclientd map sphinx replica install-replica-deps install-replica-deps-root rocksdb-local replica-local

.PHONY: update-go-deps
update-go-deps:
	@echo ">> updating Go dependencies"
	@for m in $$(go list -mod=readonly -m -f '{{ if and (not .Indirect) (not .Main)}}{{.Path}}{{end}}' all); do \
		go get $$m; \
	done
	go mod tidy
ifneq (,$(wildcard vendor))
	go mod vendor
endif

all: server dirauth genconfig ping courier replica echo-plugin fetch genkeypair geometry http-proxy-client http-proxy-server kpclientd sphinx

server:
	cd cmd/server; go build -trimpath -ldflags "-s -w"

dirauth:
	cd cmd/dirauth; go build -trimpath -ldflags "-s -w"

genconfig:
	cd cmd/genconfig; go build -trimpath -ldflags "-s -w"

ping:
	cd cmd/ping; go build -trimpath -ldflags "-s -w"

courier:
	cd cmd/courier; go build -trimpath -ldflags "-s -w"

echo-plugin:
	cd cmd/echo-plugin; go build -trimpath -ldflags "-s -w"

fetch:
	cd cmd/fetch; go build -trimpath -ldflags "-s -w"

genkeypair:
	cd cmd/genkeypair; go build -trimpath -ldflags "-s -w"

geometry:
	cd cmd/geometry; go build -trimpath -ldflags "-s -w"

http-proxy-client:
	cd cmd/http-proxy-client; go build -trimpath -ldflags "-s -w"

http-proxy-server:
	cd cmd/http-proxy-server; go build -trimpath -ldflags "-s -w"

kpclientd:
	cd cmd/kpclientd; go build -trimpath -ldflags "-s -w"

sphinx:
	cd cmd/sphinx; go build -trimpath -ldflags "-s -w"

# Privilege escalation for the system-wide RocksDB install. Defaults to sudo;
# install-replica-deps-root clears it to run the recipe as root directly.
SUDO ?= sudo

ROCKSDB_VERSION = 10.2.1
# Per-user RocksDB prefix used by the rocksdb-local / replica-local targets.
ROCKSDB_LOCAL_PREFIX ?= $(HOME)/.cache/katzenpost/rocksdb-$(ROCKSDB_VERSION)

install-replica-deps:
	@set -e; \
	echo "Checking for RocksDB $(ROCKSDB_VERSION)..."; \
	installed_ver="$$(pkg-config --modversion rocksdb 2>/dev/null || echo none)"; \
	if [ "$$installed_ver" = "$(ROCKSDB_VERSION)" ]; then \
		echo "RocksDB $(ROCKSDB_VERSION) already installed"; \
	else \
		if [ "$$installed_ver" != "none" ]; then \
			echo "RocksDB $$installed_ver found, need $(ROCKSDB_VERSION) — removing old version..."; \
			$(SUDO) rm -f /usr/local/lib/librocksdb.*; \
			$(SUDO) rm -rf /usr/local/include/rocksdb; \
			$(SUDO) rm -f /usr/local/lib/pkgconfig/rocksdb.pc; \
			$(SUDO) ldconfig; \
		else \
			echo "RocksDB not found"; \
		fi; \
		echo "Installing build dependencies..."; \
		$(SUDO) apt-get install -y \
			cmake build-essential pkg-config gcc-14 g++-14 \
			libsnappy-dev libzstd-dev liblz4-dev \
			zlib1g-dev libbz2-dev liburing-dev libgflags-dev; \
		echo "Building RocksDB $(ROCKSDB_VERSION) from source..."; \
		tmpdir="$$(mktemp -d)"; \
		cd "$$tmpdir"; \
		git clone --depth 1 --branch v$(ROCKSDB_VERSION) https://github.com/facebook/rocksdb.git; \
		cd rocksdb; \
		env CC=gcc-14 CXX=g++-14 make shared_lib -j$$(nproc); \
		echo "Installing RocksDB $(ROCKSDB_VERSION)..."; \
		$(SUDO) env CC=gcc-14 CXX=g++-14 make install-shared; \
		$(SUDO) ldconfig; \
		rm -rf "$$tmpdir"; \
		echo "RocksDB $(ROCKSDB_VERSION) installed successfully!"; \
	fi

# Build replica (requires RocksDB dependencies)
# this may require gcc-14
replica: install-replica-deps
	cd cmd/replica; CC=gcc-14 CGO_ENABLE=1 CGO_LDFLAGS="-lrocksdb -lstdc++ -lbz2 -lm -lz -lsnappy -llz4 -lzstd -luring" go build -v -trimpath -ldflags "-X github.com/carlmjohnson/versioninfo.Revision=$$(git rev-parse --short HEAD)"


# RocksDB built into a per-user prefix; lets the replica be built without root
# or sudo. Requires the compression dev libraries (install-replica-deps-root).
rocksdb-local:
	@set -e; \
	prefix="$(ROCKSDB_LOCAL_PREFIX)"; \
	if [ -e "$$prefix/lib/librocksdb.so" ]; then \
		echo "RocksDB $(ROCKSDB_VERSION) already present at $$prefix"; \
		exit 0; \
	fi; \
	command -v gcc-14 >/dev/null || { echo "gcc-14 not found; run: make install-replica-deps-root"; exit 1; }; \
	missing=""; \
	for lib in snappy zstd lz4 z bz2 uring; do \
		printf 'int main(void){return 0;}\n' | gcc-14 -x c - -l$$lib -o /dev/null 2>/dev/null || missing="$$missing $$lib"; \
	done; \
	if [ -n "$$missing" ]; then \
		echo "Missing compression libraries:$$missing"; \
		echo "Install the build dependencies once as root: make install-replica-deps-root"; \
		exit 1; \
	fi; \
	echo "Building RocksDB $(ROCKSDB_VERSION) into $$prefix ..."; \
	tmpdir="$$(mktemp -d)"; \
	cd "$$tmpdir"; \
	git clone --depth 1 --branch v$(ROCKSDB_VERSION) https://github.com/facebook/rocksdb.git; \
	cd rocksdb; \
	env CC=gcc-14 CXX=g++-14 make shared_lib -j$$(nproc); \
	env CC=gcc-14 CXX=g++-14 make install-shared INSTALL_PATH="$$prefix"; \
	rm -rf "$$tmpdir"; \
	echo "RocksDB $(ROCKSDB_VERSION) installed at $$prefix"

# Build the replica against the per-user RocksDB prefix; no root, no sudo. The
# prefix is baked in as an rpath so the binary runs without LD_LIBRARY_PATH.
replica-local: rocksdb-local
	cd cmd/replica; CC=gcc-14 CGO_ENABLED=1 \
		CGO_CFLAGS="-I$(ROCKSDB_LOCAL_PREFIX)/include" \
		CGO_LDFLAGS="-L$(ROCKSDB_LOCAL_PREFIX)/lib -Wl,-rpath,$(ROCKSDB_LOCAL_PREFIX)/lib -lrocksdb -lstdc++ -lbz2 -lm -lz -lsnappy -llz4 -lzstd -luring" \
		go build -v -trimpath -ldflags "-X github.com/carlmjohnson/versioninfo.Revision=$$(git rev-parse --short HEAD)"

# Install the replica build dependencies system-wide. Run this once as root
# (no sudo needed); then build with `make replica` as your normal user.
install-replica-deps-root:
	$(MAKE) install-replica-deps SUDO=

clean:
	rm -f cmd/server/server cmd/dirauth/dirauth cmd/genconfig/genconfig cmd/ping/ping \
		cmd/courier/courier cmd/echo-plugin/echo-plugin cmd/fetch/fetch \
		cmd/genkeypair/genkeypair cmd/geometry/geometry \
		cmd/http-proxy-client/http-proxy-client cmd/http-proxy-server/http-proxy-server \
		cmd/kpclientd/kpclientd \
		cmd/sphinx/sphinx cmd/replica/replica cmd/copycat/copycat

sphincsplus:
	cd sphincsplus/ref && go test -v -race -timeout 0 ./...

# Generate mixnet configuration files (required for tests that depend on config symlinks)
test-config:
	@echo "Generating mixnet configuration files..."
	cd docker && make config-only

# Run all unit tests (same as GitHub workflow)
test-unit: test-config
	@echo "Running authority unit tests..."
	cd authority && GORACE=history_size=7 go test -coverprofile=coverage.out -race -v -failfast -timeout 30m ./...
	@echo "Running client unit tests..."
	cd client && GORACE=history_size=7 go test -coverprofile=coverage.out -race -v -failfast -timeout 30m ./...
	@echo "Running core unit tests..."
	cd core && GORACE=history_size=7 go test -coverprofile=coverage.out -race -v -failfast -timeout 30m ./...
	@echo "Running NIKE Sphinx unit tests..."
	cd core/sphinx && GORACE=history_size=7 go test -coverprofile=coverage.out -race -v -failfast -timeout 30m ./...
	@echo "Running server unit tests..."
	cd server && GORACE=history_size=7 go test -coverprofile=coverage.out -race -v -failfast -timeout 30m ./...
	@echo "Running courier unit tests..."
	cd courier && GORACE=history_size=7 go test -coverprofile=coverage.out -race -v -failfast -timeout 30m ./...


	@echo "All unit tests completed successfully!"

# Run replica unit tests (requires RocksDB dependencies)
test-replica: test-config
	@echo "Running replica unit tests..."
	cd replica && GORACE=history_size=7 CC=gcc-14 CGO_ENABLE=1 CGO_LDFLAGS="-lrocksdb -lstdc++ -lbz2 -lm -lz -lsnappy -llz4 -lzstd -luring" go test -coverprofile=coverage.out -race -v -failfast -timeout 30m ./...
	@echo "Replica unit tests completed successfully!"

# Run replica benchmarks (requires RocksDB dependencies)
bench-replica:
	@echo "Running replica benchmarks..."
	cd replica && CC=gcc-14 CGO_ENABLE=1 CGO_LDFLAGS="-lrocksdb -lstdc++ -lbz2 -lm -lz -lsnappy -llz4 -lzstd -luring" go test -v -run=^$$ -bench=. -benchtime=3x ./...
	@echo "Replica benchmarks completed successfully!"

# Run all sphinx benchmarks
bench-sphinx:
	@echo "Running Sphinx benchmarks..."
	go test -v -run='^$$' -bench=. -benchmem ./core/sphinx/...
	@echo ""
	@echo "Sphinx benchmarks completed!"

# Run all wire handshake benchmarks (client, courier, mix server, dirauth, replica)
bench-handshake:
	@echo "Running all wire handshake benchmarks..."
	@echo ""
	@echo "=== Client2 Handshake Benchmarks ==="
	go test -v -run=^$$ -bench=. -benchtime=3x ./client/
	@echo ""
	@echo "=== Dirauth Client Handshake Benchmarks ==="
	go test -v -run=^$$ -bench=. -benchtime=3x ./authority/voting/client/
	@echo ""
	@echo "=== Dirauth Server Handshake Benchmarks ==="
	go test -v -run=^$$ -bench=. -benchtime=3x ./authority/voting/server/
	@echo ""
	@echo "=== Mix Server Incoming Handshake Benchmarks ==="
	go test -v -run=^$$ -bench=. -benchtime=3x ./server/internal/incoming/
	@echo ""
	@echo "=== Mix Server Outgoing Handshake Benchmarks ==="
	go test -v -run=^$$ -bench=. -benchtime=3x ./server/internal/outgoing/
	@echo ""
	@echo "=== Mix Server PKI Client Handshake Benchmarks ==="
	go test -v -run=^$$ -bench=. -benchtime=3x ./server/internal/pki/
	@echo ""
	@echo "=== Courier Handshake Benchmarks ==="
	go test -v -run=^$$ -bench=. -benchtime=3x ./courier/server/
	@echo ""
	@echo "=== Replica Handshake Benchmarks (requires RocksDB) ==="
	cd replica && CC=gcc-14 CGO_ENABLE=1 CGO_LDFLAGS="-lrocksdb -lstdc++ -lbz2 -lm -lz -lsnappy -llz4 -lzstd -luring" go test -v -run=^$$ -bench=. -benchtime=3x ./...
	@echo ""
	@echo "All wire handshake benchmarks completed successfully!"

# Legacy test target (kept for backwards compatibility)
test: prune-docker-cache
	go test -v -race -timeout 0 ./...

# The docker build populates docker/cache/go/pkg/mod with a module cache
# inside the repo tree. A legacy (pre-modules) dependency there has no
# go.mod of its own, so `go test ./...` walks into it and fails the whole
# pattern with "outside main module or its selected dependencies". Dropping
# a sink go.mod makes Go treat docker/cache as a separate nested module and
# prune it (and everything beneath it) from ./... . docker/cache is
# gitignored, so this file is never committed; the target recreates it.
.PHONY: prune-docker-cache
prune-docker-cache:
	@mkdir -p docker/cache
	@printf 'module katzenpost-docker-cache-sink\n\ngo 1.26\n' > docker/cache/go.mod

act-clean:
	@echo "Cleaning up docker mixnet environment..."
	-podman rm -f $$(podman ps -aq --filter "name=voting_mixnet") 2>/dev/null || true
	-cd docker && make clean-local 2>/dev/null || true
	@echo "Cleanup complete."

act: act-clean
	act --bind --container-options "-v /etc/ssl/certs:/etc/ssl/certs:ro -v /usr/share/ca-certificates:/usr/share/ca-certificates:ro -v /run/user/$(shell id -u)/podman/podman.sock:/var/run/docker.sock" -P ubuntu-latest=catthehacker/ubuntu:act-22.04 -j test_e2e_client
