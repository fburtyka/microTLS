use std::io::{self, Read};
use std::net::TcpStream;

use chrono::{DateTime, FixedOffset, TimeZone};

pub struct Messages {
    pub client_hello: Record,
    pub server_hello: Record,
    pub server_handshake: DecryptedRecord,
    pub encrypted_server_handshake: Record, // not needed
    pub application_request: Record, // not needed
    pub encrypted_ticket: Record, // not needed
    pub http_response: Record,
}


//pub type DecryptedRecord = Vec<u8>;

//impl DecryptedRecord {
    //pub fn type_(&self) -> u8 {
        //&self.last().expect("DecryptedRecord is empty")
    //}

    //pub fn contents(&self) -> &[u8] {
        //&self[..self.len() - 1]
    //}
//}

pub struct DecryptedRecord(pub(crate) Vec<u8>);

impl DecryptedRecord {

    pub fn new() -> DecryptedRecord {
        DecryptedRecord{ 0: vec![]}
    }

    // Возвращает последний байт в записи
    pub fn rtype(&self) -> u8 {
        *self.0.last().expect("DecryptedRecord is empty")
    }

    // Возвращает все байты, кроме последнего
    pub fn contents(&self) -> &[u8] {
        &self.0[..self.0.len() - 1]
    }
}

//pub type Record = Vec<u8>;

//impl Record {
    //pub fn contents(&self) -> &[u8] {
        //&self[5..]
    //}

    //pub fn rtype(&self) -> u8 {
        //*self[0].expect("Record is empty")
    //}
//}

#[derive(Clone)]
pub struct Record(pub Vec<u8>);


impl Record{
    pub fn new() -> Record {
        Record{ 0: vec![]}
    }

    pub fn contents(&self) -> &[u8] {
        &self.0[5..]
    }

    // first five bytes (TLS header) are:
    // 16 or 17 (unencrypted or encrypted)
    // 03 03 (means TLS 1.2)
    // two bytes (length of message + 4)

    pub fn spoken_len(&self) -> u16 {
        (self.0[3] as u16)*256 + (self.0[4] as u16)
    }

    pub fn rtype(&self) -> u8 {
        *self.0.first().expect("Record is empty")
    }
}

pub struct ServerHello {
    pub random: [u8;32],
    pub public_key: [u8; 32],
}

pub fn server_name(name: &str) -> Vec<u8> {
    let bytes = name.as_bytes();
    concatenate(&[
        &u16_to_bytes((name.len() + 3) as u16),
        &[0x00],
        &u16_to_bytes(name.len() as u16),
        &bytes]
    )
}

pub fn key_share(public_key: &[u8]) -> Vec<u8> {
    concatenate(&[
        &u16_to_bytes((public_key.len() + 4) as u16),
        &u16_to_bytes(0x1d).as_slice(), // x25519
        &u16_to_bytes(public_key.len() as u16).as_slice(),
        &public_key]
    )
}

pub fn trunc_end_22(message: &Vec<u8>) -> Vec<u8> {
    let mut ind = message.len() - 1;
    while message[ind]!=22 && ind>0 {
        ind = ind - 1;
    }
    message[..ind].to_vec()
}

pub fn trunc_end_23(message: &Vec<u8>) -> Vec<u8> {
    let mut ind = message.len() - 1;
    while message[ind]!=23 && ind>0 {
        ind = ind - 1;
    }
    message[..ind].to_vec()
}

pub fn contains_handshake_finish(message: &Vec<u8>) -> bool {

    for i in 0.. message.len() {
        if message[i]==20 {
            if i+3<message.len() && message[i+1]==0 && message[i+2]==0 && message[i+3]==32 {
                return true;
            }
        }
    }
    return  false;
}



pub fn parse_server_hello(buf: & [u8]) -> ServerHello {
    let mut hello = ServerHello {
        random: [0u8; 32],
        public_key: [0u8; 32],
    };
    let mut current_pos: usize = 0;

    // Пропускаем handshake type:
    current_pos = current_pos + 2; // 02 00 ("server hello") // buf.take(2);

    // Пропускаем length_of_message:
    current_pos = current_pos + 2; // buf.take(2);

    // Пропускаем tls type of message:
    current_pos = current_pos + 2; // 03 03 (client protocol version = "TLS 1.2") // buf.take(2);

    if &current_pos + 32 < buf.len() { // if let Some(random_bytes) = buf.take(32) {
        let random_bytes = &buf[current_pos..current_pos+32];
        hello.random = random_bytes.try_into().unwrap(); //hello.random.extend_from_slice(random_bytes);
        current_pos = current_pos + 32;

        let session_id_len: u8 = buf[current_pos];// let session_id_len = buf.read_u8().expect("Can t read len of session ID");
        current_pos = current_pos + 1;
        //let session_id = buf.read_bytes(session_id_len);
        current_pos = current_pos + (session_id_len as usize);

        current_pos = current_pos + 2;//buf.take(2); // cipher suite
        current_pos = current_pos + 1;// buf.take(1); // compression

        let mut dst = [0u8; 2];
        dst.clone_from_slice(&buf[current_pos..current_pos+2]);
        let extensions_len = u16::from_be_bytes(dst);//let extensions_len = buf.read_u16().expect("Can t read len of extensions!");
        //let extensions = buf.read_bytes(extensions_len);
        current_pos = current_pos + 2;

        while &current_pos+2<buf.len() { // !extensions.is_empty()
            //dst.clone_from_slice(&buf[&current_pos..&current_pos+2]);
            let typ =  u16::from_be_bytes(buf[current_pos..current_pos+2].try_into().unwrap() );//let typ = extensions.read_u16().expect("can t read type of extension");
            //current_pos = current_pos + 2;
            //let extension_length = u16::from_be_bytes(buf[&current_pos..&current_pos+2]);// let extension_length = extensions.read_u16().expect("can t read len of extension");
            //current_pos = current_pos + 2;
            //let content = &buf[&current_pos..&current_pos+&extension_length];
            //current_pos = current_pos + extension_length;
            match typ {
                0x0033 => { // key share
                    current_pos = current_pos + 4;
                    // bypass type of key
                    current_pos = current_pos + 2;//let _ = contents.read_u16().expect("can t read type of key"); // 00 1d means x25519
                    let public_key_length = u16::from_be_bytes(buf[current_pos..current_pos+2].try_into().unwrap());//let public_key_length = contents.read_u16().expect("can t read len of public key");
                    current_pos = current_pos + 2;
                    let public_key_bytes = &buf[current_pos..current_pos+(public_key_length as usize)];
                    hello.public_key = public_key_bytes.try_into().unwrap(); // hello.public_key = public_key_bytes.to_vec();
                }
                0x002b => {
                    // игнорируем версию TLS (и ее длину, всегда равную 2)
                    current_pos = current_pos + 6;
                }
                _ => {
                    let extension_len = u16::from_be_bytes(buf[current_pos..current_pos+2].try_into().unwrap());
                    current_pos = current_pos + 4;
                    current_pos = current_pos + (extension_len as usize);
                    eprintln!("unknown extension");
                }
            }
        }
    } else {
        println!("not enough len of random bytes")
    }

    hello
}

pub fn read_record(reader: &mut TcpStream) -> Record { // pub fn read_record<R: Read>(reader: &mut R) -> Record {
    let mut buf = [0u8; 5];
    reader.read_exact(&mut buf).expect("Failed to read 5 bytes");

    let length = u16::from_be_bytes(buf[3..5].try_into().unwrap() ) as usize; // let length = BigEndian::read_u16(&buf[3..5]) as usize;
    println!("length is : {:?}", length);
    let contents = read(length, reader);

    let mut record = buf.to_vec();
    record.extend_from_slice(&contents);

    Record{0:record}
}


pub fn read(length: usize, reader: &mut dyn Read) -> Vec<u8> {
    let mut buf = Vec::new();
    while buf.len() < length {
        buf.extend(read_upto(length - buf.len(), reader));
    }
    buf
}

pub fn read_upto(length: usize, reader: &mut dyn Read) -> Vec<u8> {
    let mut buf = vec![0u8; length];
    let n = reader.read(&mut buf).expect("Failed to read data");
    buf.truncate(n); // Обрезаем буфер до фактически прочитанного размера
    buf
}

// pub fn concatenate(bufs: Vec<&[u8]>) -> Vec<u8> {
pub fn concatenate(bufs: &[&[u8]]) -> Vec<u8> {
    let mut buf = Vec::new();
    for b in bufs {
        buf.extend_from_slice(b);
    }
    buf
}

pub fn u16_to_bytes(n: u16) -> [u8;2] {
    n.to_be_bytes()
}

pub fn extension(id: u16, contents: Vec<u8>) -> Vec<u8> {
    concatenate(&[
        &u16_to_bytes(id),
        &u16_to_bytes(contents.len() as u16),
        &contents]
    )
}

pub fn extract_all_items(item: &str, data: &str) -> Vec<String> {
    let target = format!("{}{}{}", r#"""#, item, r#"":"#); // Substring to search for
    let mut results = Vec::new();
    let mut start = 0;

    while let Some(start_index) = data[start..].find(&target) {

        if let Some(open_quote_pos) = data[start + start_index + target.len()..].find('"'){
            let start_pos = start + start_index + target.len() + open_quote_pos + 1; // Позиция после подстроки "n":"

            // Ищем конец подстроки
            if let Some(end_index) = data[start_pos..].find('"') {
                let end_pos = start_pos + end_index; // Конечная позиция
                results.push(data[start_pos..end_pos].to_string()); // Добавляем подстроку в результаты
                start = end_pos; // Обновляем стартовую позицию для следующего поиска
            } else {
                break; // Если кавычка не найдена, выходим из цикла
            }
        } else {break};

    }

    results // outputs an vector of found substrings
}

pub fn extract_expires(data: &str) -> i64 {
    let target = r#"Date: "#; // let target = r#"Expires: "#; // substring we are looking for
    let start= data.find(target).unwrap();
    let start_pos = start + target.len(); // position after substring
    let end = data[start_pos..].find('\n').unwrap();
    let end_pos = start_pos + end; // position after substring
    let expires_time_string = data[start_pos..end_pos].to_string();
    println!("expires_time_string is : {:?}", &expires_time_string.trim());

    let dt: DateTime<FixedOffset> = DateTime::parse_from_rfc2822(&expires_time_string.trim()).unwrap();
    let timestamp = dt.timestamp();
    println!("UTC timestamp: {}", timestamp);
    return timestamp + 19800; // Date + 19800 = Expires (for Google)
}