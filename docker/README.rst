
Katzenpost Mixnet Docker
========================

This docker-compose configuration is intended to allow mixnet developers to
locally run a test network on their development system. It is meant for testing
client and server mix network components as part of the core Katzenpost
developer work flow. It should be obvious that this docker-compose situation is
not meant for production use.


1. Run a test network
::

   git clone https://github.com/katzenpost/katzenpost.git
   cd katzenpost/docker
   make nonvoting-testnet
   cd nonvoting_authority
   docker-compose up

If your system configuration requires you to `sudo` to use docker, prefix the
`make nonvoting-testnet`  and `docker-compose up` commands with `sudo`.

2. Rebuild the mix server docker image
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
