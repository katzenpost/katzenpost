
#[macro_use]
extern crate log;
extern crate log4rs;
extern crate clap;

//extern crate log4rs_rolling_file;
extern crate futures;
extern crate rand;
extern crate grpc;
extern crate tls_api_stub;
extern crate echo_rust;

use clap::{Arg, App};
use std::path::Path;
use rand::{thread_rng, Rng};
use rand::distributions::Alphanumeric;

use log4rs::encode::pattern::PatternEncoder;
use log4rs::config::{Appender, Config, Root};
use log::LevelFilter;

use std::thread;
use std::collections::HashMap;

use echo_rust::proto::kaetzchen::{Request, Response, Params, Empty};
use echo_rust::proto::kaetzchen_grpc::{KaetzchenServer, Kaetzchen};

/// CORE_PROTOCOL_VERSION must match the plugin protocol version
/// that the server's go-plugin library is using.
const CORE_PROTOCOL_VERSION: usize = 1;

/// KAETZENPOST_PLUGIN_VERSION must match the
/// Katzenpost server plugin protocol version.
const KAETZENPOST_PLUGIN_VERSION: usize = 1;

struct Echo {
    params: HashMap<String, String>,
}

impl Echo {
    fn new() -> Echo {
        Echo {
            params: HashMap::new(),
        }
    }
}

impl Kaetzchen for Echo {

    fn on_request(&self, _m: grpc::RequestOptions, req: Request) -> grpc::SingleResponse<Response> {
        if !req.HasSURB {
            return grpc::SingleResponse::err(grpc::Error::Other("failure, SURB not found with Request"))
        }
        info!("request received");
        let mut r = Response::new();
        r.set_Payload(req.Payload);
        grpc::SingleResponse::completed(r)
    }

    fn parameters(&self, _m: grpc::RequestOptions, _empty: Empty) -> grpc::SingleResponse<Params> {
        let mut params = Params::new();
        params.set_Map(self.params.clone());
        grpc::SingleResponse::completed(params)
    }
}

fn init_logger(log_dir: &str) {
    use log4rs::append::file::FileAppender;

    let rand_string: String = thread_rng()
        .sample_iter(&Alphanumeric)
        .take(10)
        .collect();
    let log_path = Path::new(log_dir).join(format!("echo_rust_{}.log", rand_string));

    let requests = FileAppender::builder()
        .encoder(Box::new(PatternEncoder::new("{d} - {m}{n}")))
        .build(log_path)
        .unwrap();

    let config = Config::builder()
        .appender(Appender::builder().build("requests", Box::new(requests)))
        .build(Root::builder().appender("requests").build(LevelFilter::Info))
        .unwrap();
    let _handle = log4rs::init_config(config).unwrap();
}

fn main() {
    let matches = App::new("Katzenpost Echo Service written in Rust")
        .version("1.0")
        .author("David Stainton <dawuud@riseup.net>")
        .about("Functions as a plugin to be executed by the Katzenpost server.")
        .arg(Arg::with_name("log_dir")
             .short("l")
             .long("log_dir")
             .required(true)
             .value_name("DIR")
             .help("Sets the log directory.")
             .takes_value(true))
        .get_matches();
    let log_dir = matches.value_of("log_dir").unwrap();

    // Ensure log_dir exists and is a directory.
    if !Path::new(log_dir).is_dir() {
        panic!("log_dir must exist and be a directory");
    }

    // Setup logging.
    init_logger(log_dir);

    // Start our grpc service.
    info!("echo-rust starting up");
    let mut server: grpc::ServerBuilder<tls_api_stub::TlsAcceptor> = grpc::ServerBuilder::new();
    let rand_string: String = thread_rng()
        .sample_iter(&Alphanumeric)
        .take(10)
        .collect();
    let socket = format!("/tmp/rust_echo_{}.sock", rand_string);
    server.http.set_unix_addr(socket.to_string()).unwrap();
    server.add_service(KaetzchenServer::new_service_def(Echo::new()));
    server.http.set_cpu_pool_threads(4);
    let _server = server.build().expect("server");

    println!("{}|{}|unix|{}|grpc", CORE_PROTOCOL_VERSION, KAETZENPOST_PLUGIN_VERSION, socket);

    loop {
        thread::park();
    }
}
