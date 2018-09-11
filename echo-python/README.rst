

python echo service plugin for katzenpost server
------------------------------------------------

We hope that this sample python echo service plugin program
for Katzenpost will serve as an inspiring example of how
to write services for the Katzenpost mix network... in python.


server configuration example
----------------------------

In you Katzenpost server configuration TOML file you will
a configuration section that looks like this:

::
   [[Provider.PluginKaetzchen]]
     Capability = "echo"
     Endpoint = "+echo"
     Disable = false
     Command = "/home/user/gopath/src/github.com/katzenpost/server_plugins/echo-python/wrapper.sh"
     MaxConcurrency = 1
     [Provider.PluginKaetzchen.Config]
       l = "/home/user/test_mixnet/service_logs"


Note that the paths above should be replaced with the
correct path to the echo-python wrapper script and the
correct logging directory for this plugin.


the wrapper script
------------------

We've included a bash wrapper script for the purpose of setting the PYTHONPATH
before executing the python plugin. This is so that the plugin will be able to
access the protobuf generated python code.


manually generate protobuf and grpc files
-----------------------------------------

Generate both the protobufs and grpc files::

   python -m grpc_tools.protoc -I../../server/plugin/proto/ --python_out=. --grpc_python_out=. ../../server/plugin/proto/kaetzchen.proto


* See gRPC basics for Python, here:  https://grpc.io/docs/tutorials/basic/python.html


starting katzenpost server
--------------------------

Before I start the server, in the same shell I active a python
virtualenv with the grpc library installed. This makes it possible for
the katzenpost server to successfully launch the python echo service
plugin.
