warped?=false
ldflags="-buildid= -X github.com/katzenpost/katzenpost/core/epochtime.WarpedEpoch=${warped}"

test:
	go test -race -cover -v ./...

lint:
	golint ./...

test-voting:
	go test -race -cover -v ./voting/...

coverage-file:
	go test ./... -coverprofile=coverage.out

coverage-html:
	go tool cover -html=coverage.out

dirauth: clean
	cd ../cmd/dirauth && go build -trimpath -ldflags ${ldflags}

fetch: clean
	cd ../cmd/fetch && go build -trimpath -ldflags ${ldflags}

clean:
	rm -f ../cmd/fetch/fetch ../cmd/dirauth/dirauth cmd/voting/voting cmd/nonvoting/nonvoting
