
hi, what's up
=============

Hello, I am an example of how to write a Katzenpost autoresponder service.
These so called Kaetzchen services run as daemons listening to a UNIX socket.
A gRPC protocol is used to exchange messages between the mix server and the plugin
programs. You could write your plugin in any language but you REALLY like python. Fine.

Generate both the protobufs and grpc files::

   python -m grpc_tools.protoc -I../../server/common-plugin/proto/ --python_out=. --grpc_python_out=. ../../server/common-plugin/proto/kaetzchen.proto


* See gRPC basics for Python, here:  https://grpc.io/docs/tutorials/basic/python.html
