warped?=false

test:
	go test -race -cover -v ./...

lint:
	golint ./...

test-internal:
	go test -race -cover -v ./internal/...

test-voting:
	go test -race -cover -v ./voting/...

# no tests here
test-nonvoting:
	go test -race -cover -v ./nonvoting/...

coverage-file:
	go test ./... -coverprofile=coverage.out

coverage-html:
	go tool cover -html=coverage.out

cmd/dirauth/dirauth: clean
	cd cmd/dirauth && go build -trimpath

cmd/fetch/fetch: clean
	cd cmd/fetch && go build -trimpath

clean:
	rm -f cmd/fetch/fetch cmd/voting/voting cmd/nonvoting/nonvoting
