
Katzenpost Docker test network
==============================

This docker-compose configuration is intended to allow Katzenpost developers to
locally run a test network on their development system. It is meant for testing
client and server mix network components as part of the core Katzenpost
developer work flow. It should be obvious that this docker-compose situation is
not meant for production use.

1. Run a test network
::

   git clone https://github.com/katzenpost/katzenpost.git
   cd katzenpost/docker
   make run-nonvoting-testnet

If your system configuration requires you to `sudo` to use docker, prefix the
`make nonvoting-testnet`  and `docker-compose up` commands with `sudo`.

At this point, you should have a locally running network. You can hit ctrl-C to
stop it.

While the docker-compose test network is running, you can use the `make
dockerdockertest` targets in the `client` and `catshadow` directories to run
their docker tests (also in docker, but without docker-compose managing the
instance where the tests are running).

You can also connect to the test network with a catshadow client by telling it
to use the `docker/nonvoting_mixnet/catshadow.toml` configuration file.

After stopping the network, you can discard all docker images by running `make
clean-images`, and can delete the test network's data with `make clean-data`,
or run `make clean` to delete both images and data. The `make clean-local`
target will delete instance data and images, but retain the `katzenpost/deps`
image which requires network access to rebuild. This allows for quick and easy
offline development.

The docker commands in the `Makefile` are not as robust as they should be, so
watch for error messages to see if it becomes necessary to delete stray
containers which are using the images and preventing them from being deleted.

**NOTE**: between restarting your local docker mixnet you **SHOULD**
remove the state changes on disk by running the following command:
::

   make clean-data

**NOTE**: If you switch between voting and nonvoting authority mixnets then
you must run this command after shutting down the old docker composed mixnet:
::

   docker network prune
