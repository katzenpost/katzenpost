warped?=false
CGO_CFLAGS_ALLOW="-DPARAMS=sphincs-shake-256f"
ldflags="-buildid= -X github.com/katzenpost/katzenpost/core/epochtime.WarpedEpoch=${warped} -X github.com/katzenpost/katzenpost/server/internal/pki.WarpedEpoch=${warped} -X github.com/katzenpost/katzenpost/minclient/pki.WarpedEpoch=${warped}"

testnet-build:
	go mod verify
	cd cmd/server ; CGO_CFLAGS_ALLOW=-DPARAMS=sphincs-shake-256f go build -trimpath -ldflags ${ldflags}
	cd ../memspool/server/cmd/memspool ; CGO_CFLAGS_ALLOW=-DPARAMS=sphincs-shake-256f go build -trimpath -ldflags ${ldflags}
	cd ../reunion/servers/reunion_katzenpost_server ; CGO_CFLAGS_ALLOW=-DPARAMS=sphincs-shake-256f go build -trimpath -ldflags ${ldflags}
	cd ../panda/server/cmd/panda_server ; CGO_CFLAGS_ALLOW=-DPARAMS=sphincs-shake-256f go build -trimpath -ldflags ${ldflags}
	cd ../server_plugins/cbor_plugins/echo-go ; CGO_CFLAGS_ALLOW=-DPARAMS=sphincs-shake-256f go build -trimpath -o echo_server -ldflags ${ldflags}
	cd ../talek/replica ; CGO_CFLAGS_ALLOW=-DPARAMS=sphincs-shake-256f go build -trimpath -ldflags ${ldflags}

testnet-install:
	mv /go/katzenpost/server/cmd/server/server /$(net_name)/server.$(distro)
	mv /go/katzenpost/memspool/server/cmd/memspool/memspool /$(net_name)/memspool.$(distro)
	mv /go/katzenpost/reunion/servers/reunion_katzenpost_server/reunion_katzenpost_server /$(net_name)/reunion_katzenpost_server.$(distro)
	mv /go/katzenpost/panda/server/cmd/panda_server/panda_server /$(net_name)/panda_server.$(distro)
	mv /go/katzenpost/server_plugins/cbor_plugins/echo-go/echo_server /$(net_name)/echo_server.$(distro)
	mv /go/katzenpost/talek/replica/replica /$(net_name)/replica.$(distro)
