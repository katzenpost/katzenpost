warped?=true
CGO_CFLAGS_ALLOW="-DPARAMS=sphincs-shake-256f"
ldflags="-buildid= -X github.com/katzenpost/katzenpost/core/epochtime.WarpedEpoch=${warped} -X github.com/katzenpost/katzenpost/server/internal/pki.WarpedEpoch=${warped} -X github.com/katzenpost/katzenpost/minclient/pki.WarpedEpoch=${warped}"

all:
	go mod verify
	CGO_CFLAGS_ALLOW=-DPARAMS=sphincs-shake-256f go build -trimpath -ldflags ${ldflags}
