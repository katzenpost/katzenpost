
extern crate futures;
extern crate rand;
extern crate grpc;
extern crate tls_api_stub;
extern crate echo_rust;

use std::thread;
use rand::{thread_rng, Rng};
use rand::distributions::Alphanumeric;
use echo_rust::kaetzchen::{Request, Response};
use echo_rust::kaetzchen_grpc::{KaetzchenServer, Kaetzchen};


struct Echo;

impl Kaetzchen for Echo {
    fn on_request(&self, _m: grpc::RequestOptions, req: Request) -> grpc::SingleResponse<Response> {
        let mut r = Response::new();
        r.set_Payload(req.Payload);
        grpc::SingleResponse::completed(r)
    }
}

fn main() {
    let mut server: grpc::ServerBuilder<tls_api_stub::TlsAcceptor> = grpc::ServerBuilder::new();
    let rand_string: String = thread_rng()
        .sample_iter(&Alphanumeric)
        .take(10)
        .collect();
    let socket = format!("/tmp/rust_echo_{}.sock", rand_string);
    server.http.set_unix_addr(socket.to_string()).unwrap();
    server.add_service(KaetzchenServer::new_service_def(Echo));
    server.http.set_cpu_pool_threads(4);
    let _server = server.build().expect("server");

    println!("1|1|unix|{}|grpc", socket);

    loop {
        thread::park();
    }
}
