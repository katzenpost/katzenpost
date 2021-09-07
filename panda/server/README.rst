
Katzenpost mixnet PANDA service
===============================

This is a rough draft untested in memory PANDA service plugin. PANDA
stands for Phrase Automated Nym Discovery Authentication, which is a
protocol variation of EKE2, a PAKE, Password Authenticated Key
Exchange, with some design variations that allows clients to perform
the key exchanges asynchronously using a ciphertext intermediary, this
PANDA server. That is to say, this server is simple a merely
facilitates the exchanges of cryphtographic binary blobs between
clients participating in the PANDA protocol.

See **Katzenpost PANDA Autoresponder Extension** specification document:
* https://github.com/katzenpost/katzenpost/blob/master/docs/drafts/panda.txt


Usage
-----

::

   ./panda -h
   Usage of ./panda:
     -dwell_time string
        ciphertext max dwell time before garbage collection (default "336h")
     -log_dir string
        logging directory
     -log_level string
        logging level could be set to: DEBUG, INFO, NOTICE, WARNING, ERROR, CRITICAL (default "DEBUG")


Configuration
-------------

Your Katzenpost server configuration should contain
a section that looks like the following:

::

   [[Provider.PluginKaetzchen]]
     Capability = "panda"
     Endpoint = "+panda"
     Disable = false
     Command = "/home/user/test_mixnet/bin/panda"
     MaxConcurrency = 1
     [Provider.PluginKaetzchen.Config]
       log_dir = "/home/user/test_mixnet/service_logs"
       dwell_time = "200h"
