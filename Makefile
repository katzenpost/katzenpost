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
