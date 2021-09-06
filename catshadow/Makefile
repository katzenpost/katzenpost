dockerdockertest:
	docker run --network=host --rm -it -v $(shell readlink -f ..):/go/katzenpost/ katzenpost/deps \
		bash -c 'cd /go/katzenpost/catshadow/; GORACE=history_size=7 go test -tags=docker_test -race -v -run Docker'
