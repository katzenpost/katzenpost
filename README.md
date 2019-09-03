catchat
=======

A chat client (eventually) using catshadow.

## Installation

### From Source

Make sure you have a working Go environment (Go 1.11 or higher is required).
See the [install instructions](http://golang.org/doc/install.html).

You will also need Qt5 and its development headers installed.

#### Dependencies

Before you can build catchat you need to install the [Go/Qt bindings](https://github.com/therecipe/qt/wiki/Installation#regular-installation).

#### Qt5 dependencies (Ubuntu example)

    apt-get --no-install-recommends install build-essential libglib2.0-dev libglu1-mesa-dev libpulse-dev
    apt-get --no-install-recommends install libqt*5-dev qt*5-dev qt*5-doc-html qml-module-qtquick*

#### Building catchat

    export QT_PKG_CONFIG=true
    go get -u -v -tags=no_env github.com/therecipe/qt/cmd/...
    go get -d -u -v github.com/katzenpost/catchat
    cd $(go env GOPATH)/src/github.com/katzenpost/catchat
    $(go env GOPATH)/bin/qtdeploy build desktop

#### Within a Docker container

Follow the build instructions above, but instead of the last command, run:

    $(go env GOPATH)/bin/qtdeploy -docker build linux

#### Run it

    ./deploy/linux/catchat

![catchat Screenshot](/assets/screenshot.png)
