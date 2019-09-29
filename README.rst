
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


2. build the nonvoting authority docker image
::

   git clone https://github.com/katzenpost/authority.git
   cd authority
   docker build --no-cache -t katzenpost/authority .

3. run docker-compose from this repository
::

   docker-compose up


**NOTE**: between restarting your local docker mixnet you **SHOULD**
remove the state changes on disk by running the following command:
::

   git clean -ffdx
