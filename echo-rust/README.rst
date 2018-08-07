
rust echo service plugin for katzenpost server
----------------------------------------------

We hope that this sample rust echo service plugin program
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
    Command = "/home/user/test_mixnet/bin/echo_server"
    MaxConcurrency = 1
    [Provider.PluginKaetzchen.Config]
      l = "/home/user/test_mixnet/service_logs"


manually generate protobuf and grpc files
-----------------------------------------

Running a "cargo build" should autogenerate the grpc and protobuf rust
code due to our build.rs file, however, you could also manually
generate the grpc and protobuf code using a command like the
following:

::

   # set this to the location of your local github.com/katzenpost/server repo
   server=/home/user/gopath/src/github.com/katzenpost/server
   out=/home/user/gopath/src/github.com/katzenpost/server_plugins/echo-rust/src/proto
   protoc -I $server/common-plugin/proto/ $server/common-plugin/proto/kaetzchen.proto --rust-grpc_out=$out --rust_out=$out

