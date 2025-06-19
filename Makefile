
.PHONY: all test test-unit test-replica test-config sphincsplus clean server dirauth genconfig ping

all: server dirauth genconfig ping

server:
	cd cmd/server; go build

dirauth:
	cd cmd/dirauth; go build

genconfig:
	cd cmd/genconfig; go build

ping:
	cd cmd/ping; go build

clean:
	rm -f cmd/server/server cmd/dirauth/dirauth cmd/genconfig/genconfig cmd/ping/ping

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

