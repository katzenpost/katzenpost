
.PHONY: all test test-unit test-replica bench-replica bench-sphinx bench-handshake test-config sphincsplus clean server dirauth genconfig ping courier echo-plugin fetch genkeypair gensphinx http-proxy-client http-proxy-server katzencat katzencopy kpclientd map sphinx replica install-replica-deps

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

all: server dirauth genconfig ping courier echo-plugin fetch genkeypair gensphinx http-proxy-client http-proxy-server katzencat katzencopy kpclientd map sphinx

server:
	cd cmd/server; go build

dirauth:
	cd cmd/dirauth; go build

genconfig:
	cd cmd/genconfig; go build

ping:
	cd cmd/ping; go build

courier:
	cd cmd/courier; go build

echo-plugin:
	cd cmd/echo-plugin; go build

fetch:
	cd cmd/fetch; go build

genkeypair:
	cd cmd/genkeypair; go build

gensphinx:
	cd cmd/gensphinx; go build

http-proxy-client:
	cd cmd/http-proxy-client; go build

http-proxy-server:
	cd cmd/http-proxy-server; go build

katzencat:
	cd cmd/katzencat; go build

katzencopy:
	cd cmd/katzencopy; go build

kpclientd:
	cd cmd/kpclientd; go build

map:
	cd cmd/map; go build

sphinx:
	cd cmd/sphinx; go build

install-replica-deps:
	@set -e; \
	echo "Checking for RocksDB..."; \
	if ! pkg-config --exists rocksdb; then \
		echo "RocksDB missing"; \
		echo "Installing build dependencies..."; \
		sudo apt-get install -y \
			cmake build-essential pkg-config gcc-14 g++-14 \
			libsnappy-dev libzstd-dev liblz4-dev \
			zlib1g-dev libbz2-dev liburing-dev libgflags-dev; \
		echo "Building RocksDB from source..."; \
		tmpdir="$$(mktemp -d)"; \
		cd "$$tmpdir"; \
		git clone https://github.com/facebook/rocksdb.git; \
		cd rocksdb; \
		git checkout v10.2.1; \
		env CC=gcc-14 CXX=g++-14 make shared_lib -j$$(nproc); \
		echo "Installing RocksDB..."; \
		sudo make install; \
		sudo ldconfig; \
		echo "RocksDB installed successfully!"; \
	else \
		echo "Using existing RocksDB installation"; \
	fi

# Build replica (requires RocksDB dependencies)
# this may require gcc-14
replica: install-replica-deps
	cd cmd/replica; CC=gcc-14 CGO_ENABLE=1 CGO_LDFLAGS="-lrocksdb -lstdc++ -lbz2 -lm -lz -lsnappy -llz4 -lzstd -luring" go build -v -trimpath


clean:
	rm -f cmd/server/server cmd/dirauth/dirauth cmd/genconfig/genconfig cmd/ping/ping \
		cmd/courier/courier cmd/echo-plugin/echo-plugin cmd/fetch/fetch \
		cmd/genkeypair/genkeypair cmd/gensphinx/gensphinx \
		cmd/http-proxy-client/http-proxy-client cmd/http-proxy-server/http-proxy-server \
		cmd/katzencat/katzencat cmd/katzencopy/katzencopy cmd/kpclientd/kpclientd \
		cmd/map/map cmd/sphinx/sphinx cmd/replica/replica

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
	@echo "Running client2 unit tests..."
	cd client2 && GORACE=history_size=7 go test -coverprofile=coverage.out -race -v -failfast -timeout 30m ./...
	@echo "Running core unit tests..."
	cd core && GORACE=history_size=7 go test -coverprofile=coverage.out -race -v -failfast -timeout 30m ./...
	@echo "Running NIKE Sphinx unit tests..."
	cd core/sphinx && GORACE=history_size=7 go test -coverprofile=coverage.out -race -v -failfast -timeout 30m ./...
	@echo "Running server unit tests..."
	cd server && GORACE=history_size=7 go test -coverprofile=coverage.out -race -v -failfast -timeout 30m ./...
	@echo "Running courier unit tests..."
	cd courier && GORACE=history_size=7 go test -coverprofile=coverage.out -v -failfast -timeout 30m ./...

	@echo "Running map unit tests..."
	cd map && GORACE=history_size=7 go test -coverprofile=coverage.out -race -v -failfast -timeout 30m ./...
	@echo "Running stream unit tests..."
	cd stream && GORACE=history_size=7 go test -coverprofile=coverage.out -race -v -failfast -timeout 30m ./...
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

# Run all wire handshake benchmarks (client2, courier, mix server, dirauth, replica)
bench-handshake:
	@echo "Running all wire handshake benchmarks..."
	@echo ""
	@echo "=== Client2 Handshake Benchmarks ==="
	go test -v -run=^$$ -bench=. -benchtime=3x ./client2/
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
test:
	go test -v -race -timeout 0 ./...

act-clean:
	@echo "Cleaning up docker mixnet environment..."
	-podman rm -f $$(podman ps -aq --filter "name=voting_mixnet") 2>/dev/null || true
	-cd docker && make clean-local 2>/dev/null || true
	@echo "Cleanup complete."

act: act-clean
	act --bind --container-options "-v /etc/ssl/certs:/etc/ssl/certs:ro -v /usr/share/ca-certificates:/usr/share/ca-certificates:ro -v /run/user/$(shell id -u)/podman/podman.sock:/var/run/docker.sock" -P ubuntu-latest=catthehacker/ubuntu:act-22.04 -j test_e2e_client2
