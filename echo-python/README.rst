

python echo service plugin for katzenpost server
------------------------------------------------

We hope that this sample python echo service plugin program
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
     Command = "/home/user/gopath/src/github.com/katzenpost/server_plugins/echo-python/plugin.py"
     MaxConcurrency = 1
     [Provider.PluginKaetzchen.Config]
       l = "/home/user/test_mixnet/service_logs"



manually generate protobuf and grpc files
-----------------------------------------

Generate both the protobufs and grpc files::

   python -m grpc_tools.protoc -I../../server/common-plugin/proto/ --python_out=. --grpc_python_out=. ../../server/common-plugin/proto/kaetzchen.proto


* See gRPC basics for Python, here:  https://grpc.io/docs/tutorials/basic/python.html
