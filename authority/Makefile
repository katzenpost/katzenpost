warped?=false
ldflags="-X github.com/katzenpost/katzenpost/core/epochtime.WarpedEpoch=${warped} -X github.com/katzenpost/katzenpost/server/internal/pki.WarpedEpoch=${warped} -X github.com/katzenpost/katzenpost/minclient/pki.WarpedEpoch=${warped}"

test:
	go test -cover -v ./...

lint:
	golint ./...

test-internal:
	go test -cover -v ./internal/...

test-voting:
	go test -cover -v ./voting/...

# no tests here
test-nonvoting:
	go test -cover -v ./nonvoting/...

coverage-file:
	go test ./... -coverprofile=coverage.out

coverage-html:
	go tool cover -html=coverage.out

build-voting:
	go mod verify
	cd ../sphincsplus/ref/ && make && cd ../../authority
	cd cmd/voting; go build -ldflags ${ldflags}

install-voting: build-voting
	cd cmd/voting; go install -ldflags ${ldflags}

build-nonvoting:
	go mod verify
	cd ../sphincsplus/ref/ && make && cd ../../authority
	cd cmd/nonvoting; go build -ldflags ${ldflags}

install-nonvoting:
	cd cmd/nonvoting; go install -ldflags ${ldflags}
