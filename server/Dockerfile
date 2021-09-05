FROM golang:buster AS builder

LABEL authors="Christian Muehlhaeuser: muesli@gmail.com"

# Can pass --build-arg warped=true to decrease epoch period
ARG warped=false

ENV ldflags="-X github.com/katzenpost/core/epochtime.WarpedEpoch=${warped} -X github.com/katzenpost/server/internal/pki.WarpedEpoch=${warped} -X github.com/katzenpost/minclient/pki.WarpedEpoch=${warped}"


# Set the working directory for the container
WORKDIR /go/server

# Build the binary
COPY . .
RUN cd cmd/server && go build -ldflags "$ldflags"
RUN cd /go ; git clone https://github.com/katzenpost/memspool ; cd memspool/server/cmd/memspool ;  go build -ldflags "$ldflags"
RUN cd /go ; git clone https://github.com/katzenpost/reunion ; cd reunion ; cd servers/reunion_katzenpost_server ; go build -ldflags "$ldflags"
RUN cd /go ; git clone https://github.com/katzenpost/panda ; cd panda/server/cmd/panda_server ; go build -ldflags "$ldflags"
RUN cd /go ; git clone https://github.com/katzenpost/server_plugins ; cd server_plugins/cbor_plugins/echo-go ; go build -o echo_server -ldflags "$ldflags"

FROM debian:buster


COPY --from=builder /go/server/cmd/server/server /go/bin/server
COPY --from=builder /go/memspool/server/cmd/memspool/memspool /go/bin/memspool
COPY --from=builder /go/reunion/servers/reunion_katzenpost_server/reunion_katzenpost_server /go/bin/reunion_katzenpost_server
COPY --from=builder /go/panda/server/cmd/panda_server/panda_server /go/bin/panda_server
COPY --from=builder /go/server_plugins/cbor_plugins/echo-go/echo_server /go/bin/echo_server

# Expose the application port
# EXPOSE 8181

# create a volume for the configuration persistence
VOLUME /conf

# This form of ENTRYPOINT allows the process to catch signals from the `docker stop` command
ENTRYPOINT /go/bin/server -f /conf/katzenpost.toml
