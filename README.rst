
Katzenpost Mixnet Docker
========================

This docker-compose configuration is meant to be used in combination
with the **server** and **authority** repositories. It is meant for
testing client and server mix network components as part of the core
Katzenpost developer work flow. It should be obvious that this
docker-compose situation is not meant for production use.


1. build the mix server docker image
::

   git clone https://github.com/katzenpost/server.git
   cd server
   docker build --no-cache -t katzenpost/server .


2. build the authority docker image

voting authority
::

   git clone https://github.com/katzenpost/authority.git
   cd authority
   docker build -f Dockerfile.voting --no-cache -t katzenpost/voting_authority .

nonvoting authority
::

   git clone https://github.com/katzenpost/authority.git
   cd authority
   docker build -f Dockerfile.nonvoting --no-cache -t katzenpost/nonvoting_authority .


3. run docker-compose from this repository and cd into one of the folders depending on your usecase (control-c to exit)
::

   docker-compose up


**NOTE** katzenpost expects its configuration files to be readable by the owner only. Fix the permissions by:
::

   chmod 700 -R *_mixnet/conf


**NOTE**: between restarting your local docker mixnet you **SHOULD**
remove the state changes on disk by running the following command:
::

   git clean -ffdx


**NOTE**: If you switch between voting and nonvoting authority mixnets then
you must run this command after shutting down the old docker composed mixnet:
::

   docker network prune
