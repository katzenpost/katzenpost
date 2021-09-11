warped?=false
ldflags="-X github.com/katzenpost/katzenpost/core/epochtime.WarpedEpoch=${warped} -X github.com/katzenpost/katzenpost/server/internal/pki.WarpedEpoch=${warped} -X github.com/katzenpost/katzenpost/minclient/pki.WarpedEpoch=${warped}"

dockerdockertest:
	docker run --network=host --ulimit memlock=1048576 --rm -it -v $(shell readlink -f ..):/go/katzenpost/ katzenpost/deps \
		bash -c 'cd /go/katzenpost/catshadow/; GORACE=history_size=7 go test -ldflags ${ldflags} -tags=docker_test -race -v -timeout 0 -run Docker'
