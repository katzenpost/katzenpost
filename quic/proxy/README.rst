Proxy
=====

Proxy is a http proxy that proxies http Requests received on a local listening
socket to a well known katzenpost kaetzchen autoresponder, and returns the
Response to the origin client.

Usage
=====

To test the proxy client and server locally, you can use our dockerized
testnet. You'll need podman or docker and docker-compose, golang, and make.  If
you're using Debian bullseye, you'll want the newer version of golang from
bullseye-backports.

For more detailed instructions, consult the README.rst in docker/README.rst of
this repository.

Starting the testnet:
::

   git clone https://github.com/katzenpost/katzenpost
   cd katzenpost/docker
   make clean start wait

After all of the daemons have been built, deployed, and bootstrapped, you'll
have a running testnet locally.

Note that on MacOS, the "host" network namespace is actually on a linux virtual
machine so you'll need to get a shell inside that machine in order to connect
to the network. From there you can run the below commands to build and test the
client.

By default the HTTP proxy service is deployed on the "provider1" node, and is
advertising in the PKI with endpoint "http". Its configuration will be
generated automatically and put in the path
katzenpost/docker/voting_mixnet/provider1/katzenpost.toml.

For example, this is the configuration excerpt for the proxy service:
::

  [[Provider.CBORPluginKaetzchen]]
    Capability = "http"
    Endpoint = "+http"
    Command = "/voting_mixnet/proxy_server.alpine"
    MaxConcurrency = 1
    Disable = false
    [Provider.CBORPluginKaetzchen.Config]
      host = "localhost:4242"
      log_dir = "/voting_mixnet/provider1"
      log_level = "DEBUG"

This means that the service will accept proxy requests for localhost:4242 (and
only localhost:4242). You can use a wildcard "*", but this will allow any
client to make http requests to any host.

To build the proxy client, use the makefile. Note that the build flag
'warped=true' is used with the testnet in order to shorten the bootstrap time
and is not used in production, so it is not the default value in the Makefile.
::

   cd katzenpost/proxy
   make warped=true clean client/client

You'll now have a binary client/client (relative to this path). The CLI help:
::

   ./client/client -help
   Usage of ./client/client:
     -cfg string
       	config file (default "proxy.toml")
     -ep string
       	endpoint name
     -log_level string
       	logging level could be set to: DEBUG, INFO, NOTICE, WARNING, ERROR, CRITICAL (default "DEBUG")
     -port int
       	listener address (default 8000)

To start the client using the generated testnet configuration:

::

   ./client/client -ep http -cfg ../../docker/voting_mixnet/client/client.toml

Note that you can specify a different listening port (than 8080) with the -port flag.
The client will connect to the mixnet and start exchanging decoy messages (cover traffic).

You can then make requests to the proxy service, which will be forwarded to localhost:4242

Start something listening on localhost:4242 to be connected to (for example)
::

   mkdir foo && cd foo && python3 -m http.server --bind localhost 4242

And make requests to the proxy client using something that works with http proxy, e.g.:

::

   http_proxy=localhost:8080 curl -v http://localhost:4242

Note that this is a *simple* request/response service and does NOT chunk
responses larger than the mix payload size.

To adjust the mix payload size for your application, you can pass
UserForwardPayloadLength=10000 as a make argument when deploying the testnet.
This will generate a configuration for the network topology that uses 10000b
payloads. Payloads are padded, so using a very large payload will incur
overhead of small requests.


Example deploying katzenpost with larger forward payload
::

   cd katzenpost/docker && make UserForwardPayloadLength=10000 clean-local

license
=======

AGPL: see LICENSE file for details
