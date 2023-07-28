
.. image:: https://travis-ci.org/katzenpost/katzenpost.svg?branch=master
  :target: https://travis-ci.org/katzenpost/katzenpost/sockatz

.. image:: https://godoc.org/github.com/katzenpost/katzenpost/sockatz?status.svg
  :target: https://godoc.org/github.com/katzenpost/katzenpost/sockatz


Katzenpost Socket Proxy Tool
============================

Sockatz is a proxy client and server that provides reliable transport over the Katzenpost mix network using QUIC.

The client component provides a SOCKS5 listener, and the server comonent is a Katzenpost Mix Server plugin that proxies connections between hosts on the Internet and clients of Katzenpost.

Getting started
===========================

To test out Sockatz locally, start the dockerized mixnet.
See instructions in ../docker/README.rst for installation requirements.

This is experimental software. You will need to start your dockerized network with parameters that will satisfy the quic-go library used to provide reliable transport. As of now, these values have not been tuned, but experimentally chosen values for delays that look approximately like the Internet-At-Large are known to work well.

::

  git clone https://github.com/katzenpost/katzenpost
  cd katzenpost/docker && make mu=0.05 muMax=50 lP=0.2 lPMax=20 start wait


You'll now have a mixnet running with the mu, muMax, lambdaP, and lambdaPMax values overriden from defaults. For reference, the meaning of the mu, lP parameters is "the inverse of the mean of the exponential distribution" in milliseconds, therefore:

mu: 1/.05 = 20 milliseconds average delay per hop

lP: 1/.2 = 5 milliseconds average interval between packets, or ~ 200 packets per second

Note that these values are not evaluated for privacy properties

To run the end-to-end tests

::

   make dockerdockertest

To test the socks5 client, build and launch it using the configuration file generated for the test network

::

   make client/cmd/client/client
   ./client/cmd/client/client -cfg ../docker/voting_mixnet/client/client.toml

By default, the client listens on port 4242, which you can change with the -port flag. See also -help

::

  Usage of ./client/cmd/client/client:
  -cfg string
    	config file (default "sockatz.toml")
  -port int
    	listener address (default 4242)

Now point your favorite SOCKS5 supporting client at the socks proxy port, for example, with curl, set the http_proxy and https_proxy environment variables:

http_proxy=localhost:4242 https_proxy=localhost:4242 curl foo.com
