warped=false
ldflags="-buildid= -X github.com/katzenpost/katzenpost/core/epochtime.WarpedEpoch=${warped}"

server:
	cd cmd/server; go build -trimpath ;

server-pyroscope:
	cd cmd/server; go build -tags pyroscope -trimpath ;

server-pyroscope-warped-epoch:
	cd cmd/server; go build -tags pyroscope -trimpath -ldflags ${ldflags} ;
