warped?=false
CGO_CFLAGS_ALLOW="-DPARAMS=sphincs-shake-256f"
ldflags="-buildid= -X github.com/katzenpost/katzenpost/core/epochtime.WarpedEpoch=${warped} -X github.com/katzenpost/katzenpost/server/internal/pki.WarpedEpoch=${warped} -X github.com/katzenpost/katzenpost/minclient/pki.WarpedEpoch=${warped}"

all: client/client server/server

client/client:
	cd client && CGO_CFLAGS_ALLOW=-DPARAMS=sphincs-shake-256f go build -trimpath -ldflags ${ldflags}

server/server:
	cd server && CGO_CFLAGS_ALLOW=-DPARAMS=sphincs-shake-256f go build -trimpath -ldflags ${ldflags}
clean:
	rm -f client/client server/server
