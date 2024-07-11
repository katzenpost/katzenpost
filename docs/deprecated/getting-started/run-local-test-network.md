---
title: "Run a Test Network"
linkTitle: "Run a Test Network"
description: "Getting started in Katzenpost development"
weight: 20
categories: [""]
tags: ["development", "testing", "network"]
draft: false
---

The following is steps to run an actual katzenpost network from a single
computer for development testing purposes. The default is the following:

- 3x Directory Authority Nodes
- 6x Mix Nodes (1 provider node)
- 2x Chat App

## Installing

1. Install the necessary dependencies as root user

```
apt install podman docker-compose
```

Go to a workspace directory or `GOPATH` or such

```
cd ~/code/
```

2. Get the code for `katzenpost` server nodes

```
git clone https://github.com/katzenpost/katzenpost
cd katzenpost/
git fetch
git checkout -b devel
cd ../
```

3. Get code for `katzen` GUI chat app

```
git clone https://github.com/katzenpost/katzen
cd katzen/
git fetch
git checkout -b devel
cd ../
```

## Run: katzenpost servers

Run the following as non-root user and then build the code:

```
cd docker/
systemctl --user enable --now podman.socket 
make start-voting-testnet
```

If all builds correctly, it will start running multiple katzenpost nodes in
the background. You should see things like this in your terminal

```
Creating voting_mixnet_auth4_1 ... done
Creating voting_mixnet_auth1_1 ... done
Creating voting_mixnet_mix5_1      ... done
Creating voting_mixnet_provider2_1 ... done
...
```

Wait a little for things to finish starting up, then run following:

```
tail -F voting_mixnet/auth1/katzenpost.log
```

Wait for the network to get consensus for about 2 minutes


## Run: ping

Pop open another terminal and run:

```
cd ~/code/katzenpost/docker/
make run-ping
```

Observe that `ping` works correctly, then move on to testing `katzen` app


## App: katzen

Backup any non-devel non-warped katzen binary first if this would overwrite it

Then build `katzen` binary with:

```
make warped=true docker-build-linux
```

Assuming that builds with no errors, you should have a `katzen` binary wit which
you should run two instances of `katzen` GUI app (from two terminals) with:

```
./katzen -f ../katzenpost/docker/voting_mixnet/client/client.toml -s teststate1
./katzen -f ../katzenpost/docker/voting_mixnet/client/client.toml -s teststate2
```

Each app instance will prompt you to input a passphrase in each UI. Choose 
something easy like `teststate1` or such.

Then add the same identity key or `tatzen` to each chat app.

Now see if you can talk to yourself from one app to another!

---

## Stopping Servers & Cleaning Up

If you want to stop all `katzenpost` nodes from running, do the following

```
cd ~/code/katzenpost/
make clean-local
```

To delete the previous build (from same directory) run the following

```
make clean
```


