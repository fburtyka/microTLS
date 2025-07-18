extern crate core;

pub mod tls_session;
pub mod format;
pub mod network;

use tls_session::Session;

use std::io::{self, Write, BufRead, Read};
use std::net::TcpStream;
use std::fs::File;

use hex::FromHex;

/*fn val(c: u8) -> Option<u8> {
    match c {
        b'A'..=b'F' => Some(c - b'A' + 10),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'0'..=b'9' => Some(c - b'0'),
        _ => None,
    }
}

fn from_hex(hex: &str) -> Option<Vec<u8>> {
        //let hex = hex.as_ref();
    if hex.len() % 2 != 0 {
        return None;//Err(FromHexError::OddLength);
    }

    let mut result= vec![0u8; hex.len() / 2];

    for i in 0..hex.len() / 2 {
        result[i] = val(hex.get()[2 * i])? << 4 | val(hex[2 * i + 1])?;
    }

    return Some(result);
        //hex.chunks(2)
            //.enumerate()
            //.map(|(i, pair)| Some(val(pair[0], 2 * i)? << 4 | val(pair[1], 2 * i + 1)?))
            //.collect()
}*/

fn deserialize_from_hex_str(data: &str) -> Result<Vec<u8>, hex::FromHexError> {
    Vec::from_hex(data)
}

fn append_uint32(b: &mut Vec<u8>, v: u32) {
    b.push((v >> 24) as u8);
    b.push((v >> 16) as u8);
    b.push((v >> 8) as u8);
    b.push(v as u8);
}

fn mainOffline() {
    // читать файл с
    let mut file = File::open("SerializedTLS.txt").unwrap();

    let mut contents = String::new();

    // Считываем содержимое файла в строку
    file.read_to_string(&mut contents).unwrap();

    // "kid": "1bb774bd8729ea38e9c2fe0c64d2ca948bf66f0f"
    // "kid": "882503a5fd56e9f734dfba5c50d7bf48db284ae9",
    // kid: 0d8a67399e7882acae7d7f68b2280256a796a582  current_decoded_kid is : Ok([13, 138, 103, 57, 158, 120, 130, 172, 174, 125, 127, 104, 178, 40, 2, 86, 167, 150, 165, 130])

    // Выводим содержимое на экран
    println!("Содержимое файла:\n{}", contents);
    let mut tls_data = deserialize_from_hex_str(&contents).unwrap();
    println!("tls_data is : {:?}", tls_data);
    let current_timestamp = 1000u32;// SystemTime::now()
    let mut data: Vec<u8> = Vec::new();
    append_uint32(&mut data, current_timestamp);
    //let mut kid = vec![13, 138, 103, 57, 158, 120, 130, 172, 174, 125, 127, 104, 178, 40, 2, 86, 167, 150, 165, 130];//vec![0u8; 20];
    //let mut kid = hex::decode("8e8fc8e556f7a76d08d35829d6f90ae2e12cfd0d").unwrap();
    let mut kid = hex::decode("9f252dadd5f233f93d2fa528d12fea").unwrap();
    let root_cert = tls_session::get_root_cert_google_g1();
    let mut len_of_root_cert = vec![5u8, 91u8];
    data.push(kid.len() as u8);
    data.append(&mut kid);
    data.append(&mut len_of_root_cert);
    data.append(&mut root_cert.to_vec());
    data.append(&mut tls_data);

    println!("THE data is : {:?}", data);

    let public_key_data = tls_session::extract_json_public_key_from_tls(data);

    println!("public_key_data is : {:?}", public_key_data);

}

fn mainReadDer() {
    let mut file = File::open("certificate.der").unwrap();
    let mut buffer = [0u8; 1400];
    file.read(&mut buffer);
    println!("buffer is : {:?}", buffer);
}

fn main() {
    // get("jvns.ca");
    // get("https://www.googleapis.com/oauth2/v3/certs");
    get("www.googleapis.com");
    //get("kauth.kakao.com");
    //get("www.facebook.com");
}

fn get(domain: &str) {

    let mut session = Session::new(String::from(domain)).expect("Failed to connect to domain");
    session.connect();

    let req = match domain {
        "www.googleapis.com" => format!("GET /oauth2/v3/certs HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n", domain),
        "kauth.kakao.com" => format!("GET /.well-known/jwks.json HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n", domain),
        "www.facebook.com" => format!("GET /.well-known/oauth/openid/jwks HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n", domain),
        _ => format!("GET / HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n", domain)
    };
    /*let req = format!(
        "GET /.well-known/jwks.json HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
        domain
    );

    let req = format!(
        "GET /oauth2/v3/certs HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
        domain
    );*/
    println!("req.as_bytes() is : {:?}", req.as_bytes());
    session.send_data(req.as_bytes());// session.send_data(req.as_bytes()).expect("Failed to send data");


    println!("SendData done");
    // session.receive_data(); // ignore the session ticket
    let ticket = session.receive_data(); // let _ = session.receive_data(); // ignore the session ticket
    println!("ticket is : {:?}", ticket);
    println!("ReceiveData done");
    let resp = session.receive_http_response(); // let resp = session.receive_http_response().expect("Failed to receive HTTP response")
    println!("ReceiveHTTPResponse done");
    println!("{}", String::from_utf8_lossy(&resp));
    let mut serialized_session = session.serialize();
    println!("serialized_session is : {:?}", serialized_session);

    let current_timestamp = 1752495433u32;// SystemTime::now()
    let mut data: Vec<u8> = Vec::new();
    append_uint32(&mut data, current_timestamp);
    //let mut kidGoogle = vec![142, 143, 200, 229, 86, 247, 167, 109, 8, 211, 88, 41, 214, 249, 10, 226, 225, 44, 253, 13];//vec![0u8; 20];
    let mut kid = hex::decode("8e8fc8e556f7a76d08d35829d6f90ae2e12cfd0d").unwrap(); //google
    //let mut kid = hex::decode("3f96980381e451efad0d2ddd30e3d3").unwrap(); // kakao
    //let mut kidFacebook = hex::decode("e4d2003ea7326bfdadbac384ca601fef723e40ae").unwrap(); // facebook



    let mut root_cert = match domain {
        "www.googleapis.com" => tls_session::get_root_cert_google_g1().to_vec(),
        "kauth.kakao.com" => tls_session::get_root_cert_kakao().to_vec(),
        _ => tls_session::get_root_cert_facebook().to_vec(),
    };

    let mut len_of_root_cert = format::u16_to_bytes(root_cert.len() as u16).to_vec();
    println!("len_of_root_cert is : {:?}", len_of_root_cert);
    data.push(kid.len() as u8);
    data.append(&mut kid);
    data.append(&mut len_of_root_cert);
    data.append(&mut root_cert);
    data.append(&mut serialized_session);

    println!("THE data is : {:?}", data);
    let public_key_data = tls_session::extract_json_public_key_from_tls(data);

    println!("public_key_data is : {:?}", public_key_data);
}



