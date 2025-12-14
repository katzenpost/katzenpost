
.PHONY: all test test-unit test-replica test-config sphincsplus clean server dirauth genconfig ping courier echo-plugin fetch genkeypair gensphinx http-proxy-client http-proxy-server katzencat katzencopy kpclientd map sphinx replica install-replica-deps

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

# Install RocksDB dependencies required for replica
install-replica-deps:
	@echo "Installing RocksDB dependencies..."
	sudo apt-get update
	sudo apt-get install -y cmake build-essential libsnappy-dev libzstd-dev liblz4-dev libz-dev
	@echo "Installing gflags..."
	@if [ ! -f /usr/local/lib/libgflags.so ]; then \
		echo "Building gflags from source..."; \
		cd /tmp && \
		git clone https://github.com/gflags/gflags.git && \
		cd gflags && \
		mkdir build && \
		cd build && \
		cmake -DBUILD_SHARED_LIBS=1 -DGFLAGS_INSTALL_SHARED_LIBS=1 .. && \
		make -j$$(nproc) && \
		sudo make install && \
		cd /tmp && \
		rm -rf /tmp/gflags/; \
	else \
		echo "Using existing gflags installation"; \
	fi
	@echo "Installing RocksDB..."
	@if [ ! -f /usr/local/rocksdb/lib/librocksdb.so ]; then \
		echo "Building RocksDB from source..."; \
		cd /tmp && \
		git clone https://github.com/facebook/rocksdb.git && \
		cd rocksdb && \
		git checkout v10.2.1 && \
		make shared_lib -j$$(nproc) && \
		sudo mkdir -p /usr/local/rocksdb/lib && \
		sudo mkdir -p /usr/local/rocksdb/include && \
		sudo cp librocksdb.so* /usr/local/rocksdb/lib && \
		sudo cp /usr/local/rocksdb/lib/librocksdb.so* /usr/lib/ && \
		sudo cp -r include /usr/local/rocksdb/ && \
		sudo cp -r include/* /usr/include/ && \
		cd /tmp && \
		rm -rf /tmp/rocksdb/; \
	else \
		echo "Using existing RocksDB installation"; \
		sudo cp /usr/local/rocksdb/lib/librocksdb.so* /usr/lib/ 2>/dev/null || true; \
		sudo cp -r /usr/local/rocksdb/include/* /usr/include/ 2>/dev/null || true; \
	fi
	sudo ldconfig
	@echo "RocksDB dependencies installed successfully!"

# Build replica (requires RocksDB dependencies)
replica: install-replica-deps
	cd cmd/replica; go build

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
	cd replica && GORACE=history_size=7 go test -coverprofile=coverage.out -race -v -failfast -timeout 30m ./...
	@echo "Replica unit tests completed successfully!"

# Legacy test target (kept for backwards compatibility)
test:
	go test -v -race -timeout 0 ./...

act:
	act --bind --container-options "-v /etc/ssl/certs:/etc/ssl/certs:ro -v /usr/share/ca-certificates:/usr/share/ca-certificates:ro" -P ubuntu-latest=catthehacker/ubuntu:act-22.04 -j test_e2e_client2
