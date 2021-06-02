catchat
=======

[![Build Status](https://github.com/katzenpost/catchat/workflows/build/badge.svg)](https://github.com/katzenpost/catchat/actions)
[![Go ReportCard](http://goreportcard.com/badge/katzenpost/catchat)](http://goreportcard.com/report/katzenpost/catchat)
[![GoDoc](https://godoc.org/github.com/golang/gddo?status.svg)](https://pkg.go.dev/github.com/katzenpost/catchat?tab=doc)

A chat client using catshadow.

## Installation

### From Source

Make sure you have a working Go environment (Go 1.14 or higher is required; on
Debian buster the backports repository can be used).

See the [install instructions](http://golang.org/doc/install.html).

#### Installing golang (Debian Bullseye example)

    apt install golang git ca-certificates
    export GOPATH=$HOME/go

#### Dependencies (Debian Bullseye example)

    apt install --no-install-recommends build-essential libgles2 libgles2-mesa-dev libglib2.0-dev libxkbcommon-dev libxkbcommon-x11-dev libglu1-mesa-dev libxcursor-dev libwayland-dev libx11-xcb-dev

# Cross-compilation dependencies for the arm64 architecture

    dpkg --add-architecture arm64 && apt update
    apt install --no-install-recommends crossbuild-essential-arm64 libgles2:arm64 libgles2-mesa-dev:arm64 libglib2.0-dev:arm64 libxkbcommon-dev libxkbcommon-x11-dev:arm64 libglu1-mesa-dev:arm64 libxcursor-dev:arm64 libwayland-dev:arm64 libx11-xcb-dev:arm64

#### Building catchat WIP gioui branch

    git clone https://github.com/katzenpost/catchat
    cd catchat
    git checkout wip_gioui_interface
    go build

#### Building catchat, default branch

    go get -d -u -v github.com/katzenpost/catchat
    cd $(go env GOPATH)/src/github.com/katzenpost/catchat
    go build

#### Building for arm64

    CC=aarch64-linux-gnu-gcc CGO_ENABLED=1 GOOS=linux GOARCH=arm64 go build

#### Building for android

Note that you will need to have the android NDK and SDK installed and the
appropriate environment variables exported.

See the Dockerfile.android in this repository to set up a build environment if you wish.

First, get and install the gogio tool:

    go get -v gioui.org/cmd/gogio@4b377aa896373062db0f9d289d0111a29e8fa4b0

Generate an Android signing key so you can update your app later:

    keytool -genkey -keystore sign.keystore -storepass android -alias android -keyalg RSA -keysize 2048 -validity 10000 -noprompt -dname CN=android

And then build the Android APK:

    gogio -arch arm64,amd64 -x -target android -appid org.mixnetworks.catchat -version 1 -signkey sign.keystore -signpass android  .

To use the Docker environment you can do:

    docker build --no-cache -t katzenpost/android_build -f Dockerfile.android .
    docker run -v "$(pwd)":/go/build/ katzenpost/android_build gogio -arch arm64,amd64 -x -target android -appid org.mixnetworks.catchat -version 1 .

To install on an Android device using `adb` run the following

    adb install catchat.apk 

Between versions you might need to install uninstall a previous build

    adb uninstall org.mixnetworks.catchat

## Run it

    Usage of ./deploy/linux/catchat:
      -f string
         Path to the client config file. (default to baked-in testnet configuration)
      -s string
         The catshadow state file path. (default "catshadow_statefile")

![catchat Screenshot](/assets/screenshot.png)
