use std::io::{Write};

pub fn send(conn: &mut dyn Write, buf: &[u8]) { // позволяет передавать любой тип, реализующий трейт `Write
    match conn.write(buf) {
        Ok(n) => {
            if n != buf.len() {
                eprintln!("didn't send all bytes");
            }
        }
        Err(err) => {
            eprintln!("error in Send: {}", err);
        }
    }
}