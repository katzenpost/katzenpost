
daemons Releases
================

This details the releases for the ``daemons`` repository:
* https://github.com/katzenpost/daemons

At this time, there is no release schedule.

Katzenpost daemons releases follows `semantic versioning <https://semver.org/>`_.

unreleased
----------

git master will likely become v0.0.5


v0.0.4
------

September 14th, 2018
* This releases fixes some race conditions in minclient.


v0.0.3
------

September 14th, 2018
* This release adds some features such as:
  * Provider service plugin system via gRPC
  * log rotation for server and authority daemons
  * bug fix to server's external userdb
  * added the rest of the Loopix lambda parameters
    to the PKI consensus document
  * add support for loading PEM files


v0.0.2
------

August 30th, 2018
* This release adds some minor features to our core library
  and our mix server including:
  * log rotation on HUP signal
  * an HTTP account registration service
  * added a REMOVE_USER_IDENTITY thwack command
  * remove mgmt socket on server startup


v0.0.1
-------

July 10, 2018
* first release
