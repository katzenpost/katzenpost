
rust echo service plugin for katzenpost server
----------------------------------------------

omg you hate golang so much and you are so upset that
we wrote an awesome mixnet in golang. so you want to
write mixnet services in rust. fine.


to regenerate protobuf and grpc files
-------------------------------------

::

   # set this to the location of your local github.com/katzenpost/server repo
   server=/home/user/gopath/src/github.com/katzenpost/server
   out=/home/user/gopath/src/github.com/katzenpost/server_plugins/echo-rust/src
   protoc -I $server/common-plugin/proto/ $server/common-plugin/proto/kaetzchen.proto --rust-grpc_out=$out --rust_out=$out

