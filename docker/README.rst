
Katzenpost Mixnet Docker
========================

This docker-compose configuration is meant to be used in combination
with the **server** and **authority** repositories. It is meant for
testing client and server mix network components as part of the core
Katzenpost developer work flow. It should be obvious that this
docker-compose situation is not meant for production use.


1. build the mix server docker image
::

   git clone https://github.com/katzenpost/katzenpost.git
   cd katzenpost
   docker build -f docker/Dockerfile.deps --no-cache -t katzenpost/deps .
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

   git clean -ffdx


**NOTE**: If you switch between voting and nonvoting authority mixnets then
you must run this command after shutting down the old docker composed mixnet:
::

   docker network prune
