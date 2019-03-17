
extern crate rand;
extern crate hyper;
extern crate hyperlocal;
extern crate futures;

#[macro_use]
extern crate serde_derive;

#[macro_use]
extern crate serde;

#[macro_use]
extern crate serde_cbor;

use std::{fs, io};
use std::collections::HashMap;
use futures::future;
use rand::{thread_rng, Rng};
use rand::distributions::Alphanumeric;
use hyper::{header, Body, Method, StatusCode, Chunk};
use hyper::service::service_fn;
use hyper::body::Payload;
use serde::{Deserialize, Serialize};
use serde_cbor::from_slice;

#[derive(Deserialize)]
pub struct Request {
    ID: u64,
    Payload: Vec<u8>,
    HasSURB: bool,
}

#[derive(Serialize)]
pub struct Response {
    Payload: Vec<u8>,
}

type Parameters = HashMap<String, String>;

fn echo(http_request: hyper::Request<Body>) -> impl futures::Future<Item = hyper::Response<Body>, Error = io::Error> + Send {
    let mut http_response = hyper::Response::new(Body::empty());
    let mut cbor_response: Vec<u8> = Vec::new();
    match (http_request.method(), http_request.uri().path()) {
        (&Method::POST, "/request") => {
            let mut reply = Response{
                Payload: vec![],
            };

            let body = http_request.into_body();
            body.fold();
            //let req: Request = serde_cbor::from_slice().unwrap();
            //let req: Request = serde_cbor::from_reader(body_stream).unwrap();
            //let (parts, body) = http_request.into_parts();
            //let fu = Box::new(body.concat2());

            
        },
        (&Method::POST, "/parameters") => {
            // send an empty map
            let mut parameters = Parameters::new();
            cbor_response = serde_cbor::to_vec(&parameters).unwrap();
        },
        _ => {
            *http_response.status_mut() = StatusCode::NOT_FOUND;
        }
    }
    futures::future::ok(
        hyper::Response::builder()
            .header(header::CONTENT_TYPE, "application/octet-stream")
            .header(header::CONTENT_LENGTH, cbor_response.len())
            .body(hyper::Body::from(cbor_response))
            .expect("failed to create response")
   ) 
}

fn run() -> io::Result<()> {
    let rand_string: String = thread_rng()
        .sample_iter(&Alphanumeric)
        .take(10)
        .collect();
    let socket_path = format!("/tmp/rust_echo_{}.sock", rand_string);
    if let Err(err) = fs::remove_file(&socket_path) {
        if err.kind() != io::ErrorKind::NotFound {
            return Err(err);
        }
    }
    let svr = hyperlocal::server::Server::bind(&socket_path, || service_fn(echo))?;
    println!("{}\n", socket_path);
    svr.run()?;
    Ok(())
}

fn main() {
    if let Err(err) = run() {
        eprintln!("error starting server: {}", err)
    }
}
