extern crate core;

pub mod tls_session;
pub mod format;
pub mod network;

use tls_session::Session;

use std::io::{self, Write, Read};
use std::net::TcpStream;



fn main() {
    // get("jvns.ca");
    // get("https://www.googleapis.com/oauth2/v3/certs");
    get("www.googleapis.com");
}

fn get(domain: &str) {

    let mut session = Session::new(String::from(domain)).expect("Failed to connect to domain");
    session.connect();

    let req = format!(
        "GET /oauth2/v3/certs HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
        domain
    );
    println!("req.as_bytes() is : {:?}", req.as_bytes());
    session.send_data(req.as_bytes());// session.send_data(req.as_bytes()).expect("Failed to send data");

    println!("SendData done");
    // session.receive_data(); // ignore the session ticket
    let ticket = session.receive_data(); // let _ = session.receive_data(); // ignore the session ticket
    println!("ticket is : {:?}", ticket);
    println!("ReceiveData done");
    let resp = session.receive_http_response(); // let resp = session.receive_http_response().expect("Failed to receive HTTP response")
    //println!("ReceiveHTTPResponse done");
    //println!("{}", String::from_utf8_lossy(&resp));
    let serialized_session = session.serialize();
    println!("serialized_session is : {:?}", serialized_session);
}



