
rust echo service plugin for katzenpost server
----------------------------------------------

omg you hate golang so much and you are so upset that
we wrote an awesome mixnet in golang. you think you could
probably write a way better mixnet in rust but for now
you just want to write mixnet services in rust. fine.


to regenerate protobuf and grpc files
-------------------------------------

currently running a "cargo build" should autogenerate the
grpc and protobuf rust code due to our build.rs file. however,
you could also regenerate the grpc and protobuf code using
a command like the following:

::

   # set this to the location of your local github.com/katzenpost/server repo
   server=/home/user/gopath/src/github.com/katzenpost/server
   out=/home/user/gopath/src/github.com/katzenpost/server_plugins/echo-rust/src/proto
   protoc -I $server/common-plugin/proto/ $server/common-plugin/proto/kaetzchen.proto --rust-grpc_out=$out --rust_out=$out

