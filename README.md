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

You will also need Qt5 and its development headers installed.

#### Dependencies (Debian Bullseye example)

    apt-get --no-install-recommends install build-essential libglib2.0-dev libglu1-mesa-dev libpulse-dev
    apt-get --no-install-recommends install libqt*5-dev qt*5-dev qt*5-doc-html qml-module-qtquick*

#### Building catchat

    export QT_PKG_CONFIG=true
    go get -d -u -v github.com/katzenpost/catchat
    cd $(go env GOPATH)/src/github.com/katzenpost/catchat
    go get -u -v -tags=no_env github.com/therecipe/qt/cmd/...
    $(go env GOPATH)/bin/qtsetup
    go mod vendor
    $(go env GOPATH)/bin/qtdeploy build desktop

Note that you may also need to export the QT_VERSION of your systems Qt5 libraries, for example on Debian Bullseye the packaged version is 5.15.2.

    export QT_VERSION=5.15.2


### Building within a Docker container

Follow the build instructions above, but instead of the last command, run:

    $(go env GOPATH)/bin/qtdeploy -docker build linux


## Testing catchat

You can test catchat with a local mixnet. The recommended way to do
this is to first run a docker based mixnet locally, see here:

https://github.com/katzenpost/docker


Once you get your mixnet running give it a couple of minutes to get fully connected
so that it will route your messages. After that you can start catchat locally.

    cd $(go env GOPATH)/src/github.com/katzenpost/catchat
    ./deploy/linux/catchat -f ../catshadow/testdata/catshadow.toml -s bob.state -g

As you can see here, this last command uses the catshadow configuration file from the
catshadow git repo. Please aquire the catshadow repo so that you can use this configuration
file which will work with the docker mixnet you are running:

https://github.com/katzenpost/catshadow


## Run it

You only need to pass it the -g option the first time you run catchat
so that it generates a new encrypted state file.


    Usage of ./deploy/linux/catchat:
      -f string
         Path to the client config file. (default "katzenpost.toml")
      -g Generate the state file and then run client.
      -s string
         The catshadow state file path. (default "catshadow_statefile")


![catchat Screenshot](/assets/screenshot.png)
