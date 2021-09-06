
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

At this point, you can connect to the test network by configuring a catshadow
client to use the `docker/nonvoting_mixnet/catshadow.toml` configuration file.

After stopping the network, you can discard all docker images by running `make
clean-images`, and can delete the test network's data with `make clean-data`,
or run `make clean` to delete both images and data.

The docker commands in the `Makefile` are not as robust as they should be, so
watch for error messages to see if it becomes necessary to delete stray
containers which are using the images and preventing them from being deleted.

2. Rebuild the mix server docker image

If you have modified the code to a server component and wish to rebuild it, you
can delete the server image by running `docker rmi katzenpost/server`.
Subsequently, running `make nonvoting-testnet` again should re-create the image
using the previously-created katzenpost/deps image underneath any new changes
to the local checkout. If new dependencies are not introduced, it should be
possible to rebuild images using locally modified code while offline.

::

   cd ..
   docker build -f server/Dockerfile --no-cache -t katzenpost/server .


2. build the authority docker image

voting authority
::

   docker build -f authority/Dockerfile.voting --no-cache -t katzenpost/voting_authority .

nonvoting authority
::

   docker build -f authority/Dockerfile.nonvoting --no-cache -t katzenpost/nonvoting_authority .


**NOTE** katzenpost expects its configuration files to be readable by the owner only. Fix the permissions by running the fix_perms.sh script in git root:
::

    cd docker
   ./fix_perms.sh


3. cd into `voting_mixnet` (or `nonvoting_mixnet`) and run `docker-compose up` (control-c to exit)
::

   cd voting_mixnet
   docker-compose up



**NOTE**: between restarting your local docker mixnet you **SHOULD**
remove the state changes on disk by running the following command:
::

   git clean -f .


**NOTE**: If you switch between voting and nonvoting authority mixnets then
you must run this command after shutting down the old docker composed mixnet:
::

   docker network prune
