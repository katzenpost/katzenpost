
#![feature(proc_macro_hygiene, decl_macro)]

#[macro_use] extern crate rocket;

extern crate rand;

#[macro_use] extern crate serde_derive;

#[macro_use] extern crate serde;

#[macro_use] extern crate serde_cbor;

use std::{fs, io};
use std::collections::HashMap;
use rand::{thread_rng, Rng};
use rand::distributions::Alphanumeric;
use serde::{Deserialize, Serialize};
use serde_cbor::from_slice;
use rocket::{Data, Outcome, Outcome::*};
use rocket::data::{self, FromDataSimple};
use rocket::response::{self, Responder};
use rocket::http::{Status, ContentType, StatusClass};
use std::io::{Cursor, BufReader};


#[derive(Deserialize)]
pub struct Request {
    ID: u64,
    Payload: Vec<u8>,
    HasSURB: bool,
}

impl FromDataSimple for Request {
    type Error = String;

    fn from_data(req: &rocket::Request, data: Data) -> data::Outcome<Self, String> {
        // Return successfully.
        Success(Request {
                    ID: 0,
                    Payload: vec![],
                    HasSURB: true,
                })
    }
}

#[derive(Serialize)]
pub struct Response {
    Payload: Vec<u8>,
}

impl<'r> Responder<'r> for Response {
    fn respond_to(self, _: &rocket::Request) -> response::Result<'r> {
        rocket::Response::build()
            .header(ContentType::Binary)
            .sized_body(Cursor::new(self.Payload))
            .ok()
    }
}

type Parameters = HashMap<String, String>;

#[post("/request", data = "<input>")]
fn request(input: Request) -> Response {
    Response{
        Payload: input.Payload,
    }
}

#[post("/parameters")]
fn parameters() -> &'static str {
    "Hello, world!"
}

fn run() -> io::Result<()> {
    let rand_string: String = thread_rng()
        .sample_iter(&Alphanumeric)
        .take(10)
        .collect();
    let socket_path = format!("/tmp/rust_echo_{}.sock", rand_string);
    println!("{}\n", socket_path);
    rocket::ignite().mount("/", routes![request, parameters]).launch();
    Ok(())
}

fn main() {
    if let Err(err) = run() {
        eprintln!("error starting server: {}", err)
    }
}
