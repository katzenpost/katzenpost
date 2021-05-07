catchat
=======

[![Build Status](https://github.com/katzenpost/catchat/workflows/build/badge.svg)](https://github.com/katzenpost/catchat/actions)
[![Go ReportCard](http://goreportcard.com/badge/katzenpost/catchat)](http://goreportcard.com/report/katzenpost/catchat)
[![GoDoc](https://godoc.org/github.com/golang/gddo?status.svg)](https://pkg.go.dev/github.com/katzenpost/catchat?tab=doc)

A chat client using catshadow.

## Installation

### From Source

Make sure you have a working Go environment (Go 1.11 or higher is required).
See the [install instructions](http://golang.org/doc/install.html).

#### Installing golang (Debian Bullseye example)

    apt-get install golang git ca-certificates
    export GOPATH=$HOME/go

#### Dependencies (Debian Bullseye example)

    apt install --no-install-recommends build-essential libgles2 libgles2-mesa-dev libglib2.0-dev libxkbcommon-dev libxkbcommon-x11-dev libglu1-mesa-dev libxcursor-dev libwayland-dev libx11-xcb-dev

# Cross-compilation dependencies for the arm64 architecture

dpkg --add-architecture arm64 && apt update
apt install --no-install-recommends crossbuild-essential-arm64 libgles2:arm64 libgles2-mesa-dev:arm64 libglib2.0-dev:arm64 libxkbcommon-dev libxkbcommon-x11-dev:arm64 libglu1-mesa-dev:arm64 libxcursor-dev:arm64 libwayland-dev:arm64 libx11-xcb-dev:arm64

#### Building catchat

    go get -d -u -v github.com/katzenpost/catchat
    cd $(go env GOPATH)/src/github.com/katzenpost/catchat
    go build

#### Building for arm64

CC=aarch64-linux-gnu-gcc CGO_ENABLED=1 GOOS=linux GOARCH=arm64 go build

#### Building for android

gogio -arch arm64,amd64 -x -target android -appid org.mixnetworks.catchat -version 1 .

## Run it

    Usage of ./deploy/linux/catchat:
      -f string
         Path to the client config file. (default to baked-in testnet configuration)
      -s string
         The catshadow state file path. (default "catshadow_statefile")


![catchat Screenshot](/assets/screenshot.png)
