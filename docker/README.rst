
Katzenpost Docker test network
==============================

This Podman-compatible docker-compose configuration is intended to allow
Katzenpost developers to locally run an offline test network on their
development system. It is meant for developing and testing client and server
mix network components as part of the core Katzenpost developer work flow.

0. Requirements

* Podman or Docker
* either docker-compose (v1) or docker compose v2
* GNU Make

1. Run a test network
::

   git clone https://github.com/katzenpost/katzenpost.git
   cd katzenpost/docker
   make run-voting-testnet

Note that if you do not have podman and your system configuration requires you
to ``sudo`` to use docker, you will need to prefix all of the ``make`` commands
in this directory with ``sudo``. If you have both podman and docker installed,
you can override the automatic choice of podman over docker by prefixing the
``make`` argument list with ``docker=docker``.

Also note that if you are using podman, you'll need to have the podman system
service running, and pointed to by DOCKER_HOST environment variable.
::

   export DOCKER_HOST=unix:///var/run/user/$(id -u)/podman/podman.sock
   podman system service -t 0 $DOCKER_HOST &

At this point, you should have a locally running network. You can hit ctrl-C to
stop it, or use another terminal to observe the logs with ``tail -F voting_mixnet/*/*log``.

You can send pings through the network with ``make ping``.

While the docker-compose test network is running, you can use the ``make
dockerdockertest`` targets in the ``client`` and ``catshadow`` directories to
run their docker tests (also in docker, but without docker-compose managing the
instance where the tests are running). When running the docker tests, it may be
desirable to add the ``warped=true`` to the make commands (eg, ``make
warped=true run-nonvoting-testnet`` here in the docker directory, and ``make
warped=true dockerdockertest`` in the client directory) to set the WarpedEpoch
build flag.

You can also connect to the test network with a catshadow client by telling it
to use the ``docker/voting_mixnet/client/client.toml`` configuration file.

After stopping the network, you can discard all katzenpost-specific container
images by running ``make clean``, and can delete the test network's data
with ``make clean-data``, or run ``make clean`` to delete both images and data.

The ``make clean-local`` target will delete instance data and
offline-regeneratable images, but will retain the images containing
dependencies which require network access to rebuild. This allows for an
offline development workflow.

The docker/podman commands in the ``Makefile`` are not as robust as they should
be, so watch for error messages to see if it becomes necessary to delete stray
containers which are using the images and preventing them from being deleted.

**NOTE**: If you switch between voting and nonvoting authority mixnets then
you must run this command after shutting down the old docker composed mixnet:
::

   docker network prune
