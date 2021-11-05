warped?=false
ldflags="-X github.com/katzenpost/katzenpost/core/epochtime.WarpedEpoch=${warped} -X github.com/katzenpost/katzenpost/server/internal/pki.WarpedEpoch=${warped} -X github.com/katzenpost/katzenpost/minclient/pki.WarpedEpoch=${warped}"

testnet-build:
	go mod verify
	cd cmd/server ; go build -ldflags ${ldflags}
	cd ../memspool/server/cmd/memspool ; go build -ldflags ${ldflags}
	cd ../reunion/servers/reunion_katzenpost_server ; go build -ldflags ${ldflags}
	cd ../panda/server/cmd/panda_server ; go build -ldflags ${ldflags}
	cd ../server_plugins/cbor_plugins/echo-go ; go build -o echo_server -ldflags ${ldflags}

testnet-install:
	cp /go/katzenpost/server/cmd/server/server /go/bin/server
	cp /go/katzenpost/memspool/server/cmd/memspool/memspool /go/bin/memspool
	cp /go/katzenpost/reunion/servers/reunion_katzenpost_server/reunion_katzenpost_server /go/bin/reunion_katzenpost_server
	cp /go/katzenpost/panda/server/cmd/panda_server/panda_server /go/bin/panda_server
	cp /go/katzenpost/server_plugins/cbor_plugins/echo-go/echo_server /go/bin/echo_server
