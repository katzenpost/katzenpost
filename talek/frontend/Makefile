warped?=false
ldflags="-buildid= -X github.com/katzenpost/katzenpost/core/epochtime.WarpedEpoch=${warped} -X github.com/katzenpost/katzenpost/server/internal/pki.WarpedEpoch=${warped} -X github.com/katzenpost/katzenpost/minclient/pki.WarpedEpoch=${warped}"

frontend:
	go mod verify
	go build -trimpath -ldflags ${ldflags}
clean:
	rm -f frontend
all: clean frontend
