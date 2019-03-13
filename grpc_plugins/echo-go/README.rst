
external golang echo service plugin for katzenpost server
---------------------------------------------------------

We hope that this sample golang echo service plugin program
for Katzenpost will serve as an inspiring example of how
to write micro-services for the Katzenpost mix network.

server configuration example
----------------------------

Note that the following paths should be replaced with the
path to the echo service executable file and the log directory:

::

   [[Provider.PluginKaetzchen]]
     Capability = "echo"
     Endpoint = "+echo"
     Disable = false
     Command = "/home/user/test_mixnet/bin/echo-go"
     MaxConcurrency = 1
     [Provider.PluginKaetzchen.Config]
       log_dir = "/home/user/test_mixnet/service_logs"
