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

    apt-get --no-install-recommends install build-essential libgles2 libgles2-mesa-dev libglib2.0-dev libxkbcommon-dev libxkbcommon-x11-dev libglu1-mesa-dev libxcursor-dev

#### Building catchat

    go get -d -u -v github.com/katzenpost/catchat
    cd $(go env GOPATH)/src/github.com/katzenpost/catchat
    go build

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
      -s string
         The catshadow state file path. (default "catshadow_statefile")


![catchat Screenshot](/assets/screenshot.png)
