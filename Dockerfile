FROM golang:alpine AS builder

LABEL authors="Christian Muehlhaeuser: muesli@gmail.com"

# Install git & make
# Git is required for fetching the dependencies
RUN apk update && \
    apk add --no-cache git make ca-certificates && \
    update-ca-certificates

# Set the working directory for the container
WORKDIR /go/server

# Build the binary
COPY . .
RUN cd cmd/server && go build
RUN cd /go ; git clone https://github.com/katzenpost/memspool.git ; cd memspool/server/cmd/memspool ;  go build
RUN cd /go ; git clone https://github.com/katzenpost/panda.git ; cd panda/server/cmd/panda_server ; go build

FROM alpine

RUN apk update && \
    apk add --no-cache ca-certificates tzdata && \
    update-ca-certificates

COPY --from=builder /go/server/cmd/server/server /go/bin/server
COPY --from=builder /go/memspool/server/cmd/memspool/memspool /go/bin/memspool
COPY --from=builder /go/panda/server/cmd/panda_server/panda_server /go/bin/panda_server

# Expose the application port
# EXPOSE 8181

# create a volume for the configuration persistence
VOLUME /conf

# This form of ENTRYPOINT allows the process to catch signals from the `docker stop` command
ENTRYPOINT /go/bin/server -f /conf/katzenpost.toml
