
Katzenpost Mixnet Docker
========================

This docker-compose configuration is meant to be used in combination
with the **server** and **authority** repositories.

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
