FROM katzenpost/deps AS builder

# note: this Dockerfile is intended to be built from a build context that
# includes the parent directory. eg, from the katzenpost repo, run this:
# docker build -f server/Dockerfile --no-cache -t katzenpost/server .

# Can pass --build-arg warped=true to decrease epoch period
ARG warped=false

ENV ldflags="-X github.com/katzenpost/katzenpost/core/epochtime.WarpedEpoch=${warped} -X github.com/katzenpost/katzenpost/server/internal/pki.WarpedEpoch=${warped} -X github.com/katzenpost/katzenpost/minclient/pki.WarpedEpoch=${warped}"


# Set the working directory for the container
WORKDIR /go/katzenpost

# Build the binary
RUN cd server/cmd/server && go build -ldflags "$ldflags"
RUN cd /go/katzenpost/memspool/server/cmd/memspool ; go build -ldflags "$ldflags"
RUN cd /go/katzenpost/reunion/servers/reunion_katzenpost_server ; go build -ldflags "$ldflags"
RUN cd /go/katzenpost/panda/server/cmd/panda_server ; go build -ldflags "$ldflags"
RUN cd /go/katzenpost/server_plugins/cbor_plugins/echo-go ; go build -o echo_server -ldflags "$ldflags"

FROM debian:buster


COPY --from=builder /go/katzenpost/server/cmd/server/server /go/bin/server
COPY --from=builder /go/katzenpost/memspool/server/cmd/memspool/memspool /go/bin/memspool
COPY --from=builder /go/katzenpost/reunion/servers/reunion_katzenpost_server/reunion_katzenpost_server /go/bin/reunion_katzenpost_server
COPY --from=builder /go/katzenpost/panda/server/cmd/panda_server/panda_server /go/bin/panda_server
COPY --from=builder /go/katzenpost/server_plugins/cbor_plugins/echo-go/echo_server /go/bin/echo_server

# Expose the application port
# EXPOSE 8181

# create a volume for the configuration persistence
VOLUME /conf

# This form of ENTRYPOINT allows the process to catch signals from the `docker stop` command
ENTRYPOINT /go/bin/server -f /conf/katzenpost.toml
