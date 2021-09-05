

#[macro_use]
extern crate log;
extern crate log4rs;
extern crate clap;
extern crate rand;
extern crate hyper;
extern crate futures;

#[macro_use] extern crate serde_derive;

#[macro_use] extern crate serde;

#[macro_use] extern crate serde_cbor;

extern crate serde_bytes;

use std::path::Path;
use std::str;
use std::{fs, io};
use std::collections::HashMap;
use clap::{Arg, App};
use log4rs::encode::pattern::PatternEncoder;
use log4rs::config::{Appender, Config, Root};
use log::LevelFilter;
use futures::future;
use futures::{Future, Stream};
use hyper::{header, Method, StatusCode, Chunk};
use hyper::service::service_fn;
use hyper::Error;
use hyper::body::Payload;
use hyper::Body;
use rand::{thread_rng, Rng};
use rand::distributions::Alphanumeric;
use serde::{Deserialize, Serialize};
use serde_cbor::from_slice;



#[derive(Deserialize)]
#[allow(non_snake_case)]
pub struct Request {
    ID: u64,
    #[serde(with = "serde_bytes")]
    Payload: Vec<u8>,
    HasSURB: bool,
}


#[derive(Serialize)]
#[allow(non_snake_case)]
pub struct Response {
    #[serde(with = "serde_bytes")]
    Payload: Vec<u8>,
}


type Parameters = HashMap<String, String>;


type BoxFut = Box<Future<Item = hyper::Response<hyper::Body>, Error = hyper::Error> + Send>;

fn echo(req: hyper::Request<Body>) -> BoxFut {
    let mut response = hyper::Response::new(Body::empty());
    match (req.method(), req.uri().path()) {
        (&Method::POST, "/parameters") => {
            let params = Parameters::new();
            let cbor_params = serde_cbor::to_vec(&params).unwrap();
            *response.body_mut() = Body::from(cbor_params);
        }

        (&Method::POST, "/request") => {
            let _response = req.into_body().concat2().map(move |chunk| {
                let body = chunk.iter().cloned().collect::<Vec<u8>>();
                let body_result: Result<Request, serde_cbor::error::Error> = serde_cbor::from_slice(&body.to_vec());
                match body_result {
                    Ok(request) =>{
                        let inner_response = Response {
                            Payload: request.Payload,
                        };
                        let cbor_response_result = serde_cbor::to_vec(&inner_response);
                        match cbor_response_result {
                            Ok(cbor_response) => {
                                *response.body_mut() = Body::from(cbor_response);
                                return response;
                            },
                            Err(_e) => {
                                info!("FAILED to serialize CBOR response: {}", _e);
                                return response;
                            },
                        }
                    },
                    Err(_e) => {
                        info!("FAILED to deserialize CBOR request: {}", _e);
                        return response;
                    },
                }
            });
            return Box::new(_response);
        }

        // The 404 Not Found route...
        _ => {
            *response.status_mut() = StatusCode::NOT_FOUND;
        }
    };

    Box::new(future::ok(response))
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

fn run() -> io::Result<()> {
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

    info!("starting Katzenpost Echo Service");
    // Start our service
    let rand_string: String = thread_rng()
        .sample_iter(&Alphanumeric)
        .take(10)
        .collect();
    let socket_path = format!("/tmp/rust_echo_{}.sock", rand_string);
    let svr = hyperlocal::server::Server::bind(&socket_path, || service_fn(echo))?;
    println!("{}\n", socket_path);
    svr.run()?;
    info!("shutting down Katzenpost Echo Service...");
    Ok(())
}

fn main() {
    if let Err(err) = run() {
        eprintln!("error starting server: {}", err)
    }
}
