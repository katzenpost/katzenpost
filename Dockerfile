FROM golang:buster AS builder

LABEL authors="Masala: masala@riseup.net"

# Install build requirements
RUN apt update \
&& apt install --no-install-recommends -y git make ca-certificates \
build-essential libgles2 libgles2-mesa-dev libglib2.0-dev \
libxkbcommon-dev libxkbcommon-x11-dev libglu1-mesa-dev libxcursor-dev \
libwayland-dev libx11-xcb-dev \
&& update-ca-certificates
WORKDIR /go/catchat
COPY . .
RUN go mod verify
RUN go build
