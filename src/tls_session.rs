//mod tls_format;
mod x25519;
mod hkdf_sha256;
mod aes256gcm;

use x25519::curve25519_donna;
use format::*;
use network::send;
use hkdf_sha256::*;

use std::io::{self, Write, Read};
use std::net::TcpStream;
use std::ops::Mul;


use rand::{RngCore, thread_rng};
use crate::{network, format}; // Для генерации случайных данных

pub struct Keys {
    pub public: [u8; 32],
    pub private: [u8; 32],//Vec<u8>,
    pub server_public: Vec<u8>,
    pub handshake_secret: [u8;32],
    pub client_handshake_secret: [u8;32],
    pub client_handshake_key: [u8;16],
    pub server_handshake_key: [u8;16],
    pub client_handshake_iv: [u8;12],
    pub server_handshake_iv: [u8;12],
    pub client_application_key: [u8;16],
    pub client_application_iv: [u8;12],
    pub server_application_key: [u8;16],
    pub server_application_iv: [u8;12],
}

//pub fn random(bytes: usize) -> Vec<u8> {
    //let mut buf = vec![0u8; bytes];
    //rand::thread_rng().fill_bytes(&mut buf);
    //buf
//}


pub fn random32bytes() -> [u8; 32] {
    let mut buf = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut buf);
    buf
}

pub fn key_pair() -> Keys {
    //let private_key = random(32);
    //println!("private_key {:?}", private_key);
    //let private_key = random32bytes();
    let private_key = [231, 226, 189, 128, 175, 192, 46, 233, 160, 243, 227, 168, 186, 174, 207, 111, 124, 21, 6, 220, 18, 155, 18, 17, 39, 165, 203, 108, 109, 3, 40, 186];
    let basepoint:[u8;32] = [9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let public_key = curve25519_donna(&private_key, &basepoint);
    println!("private_key {:?}", private_key);
    println!("public_key {:?}", public_key);

    Keys {
        public: public_key, // public_key.compress().to_bytes().to_vec(),
        private: private_key,
        server_public: Vec::new(),
        handshake_secret: [0u8;32],
        client_handshake_secret: [0u8;32],
        client_handshake_key: [0u8;16],
        server_handshake_key: [0u8;16],
        client_handshake_iv: [0u8;12],
        server_handshake_iv: [0u8;12],
        client_application_key: [0u8;16],
        client_application_iv: [0u8;12],
        server_application_key: [0u8;16],
        server_application_iv: [0u8;12],
    }
}

// AEAD helper functions

fn decrypt(key: &[u8;16], iv: &[u8;12], wrapper: &[u8]) -> Vec<u8> {

    let block = aes256gcm::new_cipher(key);
    let aes_gcm = aes256gcm::new_gcm(block);

    let additional = &wrapper[0..5];
    let ciphertext = &wrapper[5..];

    let plaintext = aes_gcm.open(&[], iv, ciphertext, additional);
    println!("plaintext is : {:?}", plaintext);
    return plaintext;
}

fn encrypt(key: &[u8;16], iv: &[u8], plaintext: &[u8], additional: &[u8]) -> Vec<u8> {
    //let key = Key::from_slice(key);
    //let aesgcm = Aes256Gcm::new(key);
    let block = aes256gcm::new_cipher(key);
    let aes_gcm = aes256gcm::new_gcm(block);

    //let nonce = Nonce::from_slice(iv); // 96-bits; retrieve nonce from the IV
    //let ciphertext = aesgcm.encrypt(nonce, additional, plaintext).expect("Encryption failed");
    let ciphertext = aes_gcm.seal(&[], iv, plaintext, additional);

    [additional.to_vec(), ciphertext].concat() // Concatenate additional data with ciphertext
}

pub fn hkdf_expand_label(secret: &[u8;32], label: &str, context: &[u8], length: u16) -> Vec<u8> {
    //let mut hkdf_label = Vec::new();
    //hkdf_label.extend(&(length as u16).to_be_bytes());
    //hkdf_label.push(&(label.len() as u8));
    //hkdf_label.extend(b"tls13 ");
    //hkdf_label.extend(label.as_bytes());
    //hkdf_label.push(&(context.len() as u8));
    //hkdf_label.extend(context);
    // Construct HKDF label
    let mut hkdf_label = vec![];
    hkdf_label.extend_from_slice(&length.to_be_bytes());
    let tls13_prefix = b"tls13 ";
    hkdf_label.push((tls13_prefix.len()+label.as_bytes().len()) as u8);
    hkdf_label.extend_from_slice(tls13_prefix);
    hkdf_label.extend_from_slice(label.as_bytes());
    println!("hkdf_label after label add is : {:?}", hkdf_label);

    hkdf_label.push(context.len() as u8);
    hkdf_label.extend_from_slice(context);

    println!("hkdf_label is : {:?}", hkdf_label);
    println!("secret is : {:?}", &secret);

    // Expand using HKDF
    let mut reader = hkdf_sha256::expand(secret, &hkdf_label[..]);//let hkdf = Hkdf::<Sha256>::new(Some(secret), &hkdf_label);
    //let mut buf = vec![0u8; length as usize];
    //reader.read(&mut buf);//hkdf.expand(&[], &mut buf).expect("HKDF expand failed");
    println!("length is : {:?}", length);
    let buf = reader.read(length as usize);
    println!("hkdf expand result is is : {:?}", &buf);

    //let hkdf = Hkdf::<Sha256>::from_prk(secret).unwrap();// let hkdf = Hkdf::<Sha256>::from_seed(secret).unwrap();
    //let mut buf = vec![0u8; length];
    //hkdf.expand(&hkdf_label, &mut buf).unwrap();

    buf
}

pub fn derive_secret(secret: &[u8;32], label: &str, transcript_messages: &[u8]) -> [u8; 32] {

    println!("derive_secret transcript_messages is : {:?}", &transcript_messages);
    let hash = hkdf_sha256::sum256( transcript_messages);
    println!("derive_secret hash is : {:?}", &hash);
    let secret = hkdf_expand_label(secret, label, &hash, 32);
    secret.try_into().unwrap()

}

pub struct Session {
    domain_name:        String,
    conn:               TcpStream,
    server_hello:       format::ServerHello,
    messages:           format::Messages,
    keys:               Keys,
    records_sent:       u8,
    records_received:   u8,
}

impl Session {

    pub fn new(domain: String) -> io::Result<Self> {
        let stream = TcpStream::connect(format!("{}:443", domain))?;
        let keys = key_pair();
        Ok(Session {
            domain_name: domain,
            conn: stream,
            server_hello: ServerHello{random: [0u8;32], public_key: [0u8;32]},
            messages: Messages{client_hello: Record::new(), server_hello: Record::new(), server_handshake: DecryptedRecord::new()},
            keys: keys,
            records_sent: 0,
            records_received:0
        })
    }

    pub fn connect(&mut self) {
        self.send_client_hello();
        println!("SendClientHello done");
        self.get_server_hello();
        println!("GetServerHello done");
        self.make_handshake_keys();
        println!("MakeHandshakeKeys done");
        self.parse_server_handshake();
        println!("ParseServerHandshake done");
        self.client_change_cipher_spec();
        println!("ClientChangeCipherSpec done");
        self.client_handshake_finished();
        println!("ClientHandshakeFinished done");
    }

    pub fn send_client_hello(&mut self) {
        // send client hello
        let mut conn = &self.conn;
        //self.Keys = key_pair();
        let client_hello = Self::client_hello(&self.domain_name, &self.keys);
        self.messages.client_hello = Record{0:client_hello.to_vec()};
        network::send(&mut conn, &client_hello);
    }

    pub fn get_server_hello(&mut self) {
        let mut record = format::read_record(&mut self.conn);
        if record.rtype() != 0x16 {
            //panic("expected server hello")
            println!("expected server hello ")
        }

        self.messages.server_hello = record.clone();
        let hello = format::parse_server_hello(&mut record.contents());
        self.server_hello = hello;

        // ignore change cipher spec 14 03 03
        let record = format::read_record(&mut self.conn); // let record = tls_format::ReadRecord(&self.conn);
        if record.rtype() != 0x14 {
            //panic("expected change cipher spec")
            println!("expected change cipher spec")
        }
    }

    fn parse_server_handshake(&mut self) {
        let record = format::read_record(&mut self.conn);
        //format::PrintByteArray(record);
        if record.rtype() != 0x17 {
            panic!("expected wrapper (ParseServerHandshake)");
            println!("expected wrapper (ParseServerHandshake)");
        }

        println!("self.keys.server_handshake_key is : {:?}", &self.keys.server_handshake_key);
        println!("self.keys.server_handshake_iv is : {:?}", &self.keys.server_handshake_iv);
        println!("record.0[..] is : {:?}", &record.0[..]);
        let server_handshake_message = decrypt(&self.keys.server_handshake_key, &self.keys.server_handshake_iv, &record.0[..]);
        println!("server_handshake_message is : {:?}", &server_handshake_message);
        self.messages.server_handshake = DecryptedRecord{ 0: server_handshake_message};
        //format::PrintByteArray(session.Messages.ServerHandshake)
        self.make_application_keys();
    }

    pub fn make_application_keys(&mut self) {
        let handshake_messages = format::concatenate( &[
            &self.messages.client_hello.contents(),
            &self.messages.server_hello.contents(),
            &self.messages.server_handshake.contents()]
        );

        let zeros = [0u8; 32];
        let derived_secret = derive_secret(&self.keys.handshake_secret, "derived", &[]);
        let master_secret = hkdf_sha256::extract(&zeros, &derived_secret);//let master_secret = Hkdf::<Sha256>::extract(Some(&zeros), &derived_secret);

        let c_ap_secret = derive_secret(&master_secret, "c ap traffic", &handshake_messages);
        self.keys.client_application_key = hkdf_expand_label(&c_ap_secret, "key", &[], 16).try_into().unwrap();
        self.keys.client_application_iv = hkdf_expand_label(&c_ap_secret, "iv", &[], 12).try_into().unwrap();

        let s_ap_secret = derive_secret(&master_secret, "s ap traffic", &handshake_messages);
        self.keys.server_application_key = hkdf_expand_label(&s_ap_secret, "key", &[], 16).try_into().unwrap();
        self.keys.server_application_iv = hkdf_expand_label(&s_ap_secret, "iv", &[], 12).try_into().unwrap();
    }

    fn client_change_cipher_spec(&mut self){
        network::send(&mut self.conn, &[0x14, 0x03, 0x03, 0x00, 0x01, 0x01]);
    }

    fn client_handshake_finished(&mut self){
        let client_handshake_finished_msg = self.client_handshake_finished_msg();
        network::send(&mut self.conn, &client_handshake_finished_msg[..]);
    }

    fn client_handshake_finished_msg(&self) -> Vec<u8> {
        let verify_data = self.verify_data();

        // Создаем сообщение, используя verify_data и дополнительные байты
        let mut msg = Vec::new();
        msg.extend_from_slice(&[0x14, 0x00, 0x00, 0x20]); // первые 4 байта
        msg.extend_from_slice(&verify_data); // Добавляем verify_data
        msg.push(0x16); // добавляем последний байт

        let additional = [0x17, 0x03, 0x03, 0x00, 0x35];

        // Шифруем сообщение
        let encrypted = encrypt(
            &self.keys.client_handshake_key,
            &self.keys.client_handshake_iv,
            &msg,
            &additional,
        );

        encrypted
    }

    pub fn make_handshake_keys(&mut self) {
        let zeros = [0u8; 32];
        let psk = [0u8; 32]; // Предполагается, что psk инициализируется где-то

        //println!("self.keys.private is : {:?}", &self.keys.private);
        //self.server_hello.public_key=[246, 48, 130, 234, 125, 96, 179, 219, 52, 226, 168, 235, 57, 47, 53, 103, 96, 246, 129, 101, 202, 83, 142, 117, 64, 20, 47, 242, 241, 212, 56, 30];
        //println!("&self.server_hello.public_key is : {:?}", &self.server_hello.public_key);
        let shared_secret = curve25519_donna(&self.keys.private, &self.server_hello.public_key); //let shared_secret = X25519::from_slice(&self.keys.private).mul(&self.server_hello.public_key);
        println!("shared_secret is : {:?}", shared_secret);

        // Хэндшейк с использованием HKDF
        let early_secret = hkdf_sha256::extract(&zeros,&psk); //let (early_secret, hkdf) = Hkdf::<Sha256>::extract(Some(&zeros), &psk);

        println!("early_secret is : {:?}", early_secret);
        let derived_secret = derive_secret(&early_secret, "derived", &[]);
        println!("derived_secret is : {:?}", derived_secret);
        self.keys.handshake_secret = hkdf_sha256::extract(&shared_secret, &derived_secret);//self.keys.handshake_secret = Hkdf::<Sha256>::extract(Some(&shared_secret), &derived_secret);
        println!("self.keys.handshake_secret is : {:?}", self.keys.handshake_secret);

        let handshake_messages = format::concatenate(
            &[&self.messages.client_hello.contents(),
            &self.messages.server_hello.contents()]
        );
        println!("handshake_messages is : {:?}", handshake_messages);
        //let handshake_messages = vec![1, 0, 0, 157, 3, 3, 27, 126, 189, 42, 117, 227, 85, 44, 186, 155, 29, 86, 176, 221, 181, 209, 227, 24, 67, 227, 112, 232, 244, 106, 59, 250, 1, 175, 102, 253, 52, 236, 0, 0, 2, 19, 1, 1, 0, 0, 114, 0, 0, 0, 23, 0, 21, 0, 0, 18, 119, 119, 119, 46, 103, 111, 111, 103, 108, 101, 97, 112, 105, 115, 46, 99, 111, 109,
                                      //0, 10, 0, 4, 0, 2, 0, 29, 0, 13, 0, 20, 0, 18, 4, 3, 8, 4, 4, 1, 5, 3, 8, 5, 5, 1, 8, 6, 6, 1, 2, 1, 0, 51, 0, 38, 0, 36, 0, 29, 0, 32, 192, 66, 56, 95, 6, 86, 129, 217, 28, 232, 5, 177, 109, 189, 139, 154, 6, 3, 215, 62, 202, 195, 214, 238, 231, 82, 157, 198, 107, 200, 81, 16, 0, 45, 0, 2, 1, 1, 0, 43, 0, 3, 2, 3, 4, 2, 0, 0, 86, 3, 3, 8, 215, 19, 207, 58, 155, 125, 3, 157, 121, 43, 159, 152, 229, 77, 159, 41, 50, 150, 5, 171, 174, 144, 47, 121, 11, 241, 132, 255, 77, 16, 244, 0, 19, 1, 0, 0, 46, 0, 51, 0, 36, 0, 29, 0, 32, 246, 48, 130, 234, 125, 96, 179, 219, 52, 226, 168, 235, 57, 47, 53, 103, 96, 246, 129, 101, 202, 83, 142, 117, 64, 20, 47, 242, 241, 212, 56, 30, 0, 43, 0, 2, 3, 4];

        let c_hs_secret = derive_secret(&self.keys.handshake_secret, "c hs traffic", &handshake_messages);
        self.keys.client_handshake_secret = c_hs_secret.clone();
        self.keys.client_handshake_key = hkdf_expand_label(&c_hs_secret, "key", &[], 16).try_into().unwrap();
        //println!("self.keys.client_handshake_key is : {:?}", self.keys.client_handshake_key);
        self.keys.client_handshake_iv = hkdf_expand_label(&c_hs_secret, "iv", &[], 12).try_into().unwrap();
        //println!("self.keys.client_handshake_iv is : {:?}", self.keys.client_handshake_iv);

        let s_hs_secret = derive_secret(&self.keys.handshake_secret, "s hs traffic", &handshake_messages);
        //let session_keys_server_handshake_key = hkdf_expand_label(&s_hs_secret, "key", &[], 16);
        //println!("session_keys_server_handshake_key_ is : {:?}", &session_keys_server_handshake_key);
        println!("s_hs_secret is : {:?}", s_hs_secret);
        self.keys.server_handshake_key = hkdf_expand_label(&s_hs_secret, "key", &[], 16).try_into().unwrap();
        self.keys.server_handshake_iv = hkdf_expand_label(&s_hs_secret, "iv", &[], 12).try_into().unwrap();
    }

    pub fn verify_data(&self) -> Vec<u8> {
        let finishedKey = hkdf_expand_label(&self.keys.client_handshake_secret, "finished", &[], 32);
        let handshake_log = format::concatenate(&[
            self.messages.client_hello.contents(), self.messages.server_hello.contents(), self.messages.server_handshake.contents()] );
        let finishedHash = hkdf_sha256::sum256(&handshake_log[..]);
        let mut hm = Hmac::new(&finishedKey);
        hm.write(&finishedHash);
        hm.sum(&[])
    }

    //pub fn send_data(&mut self, data: &[u8]) -> io::Result<()> {
        //self.conn.write_all(data)?;
        //Ok(())
    //}
    pub fn send_data(&mut self, data: &[u8]) {
        let msg = self.encrypt_application_data(&data);
        self.records_sent +=1;
        self.conn.write(&msg[..]);// self.conn.write_all(data)?;
    }

    //pub fn receive_data(&mut self) -> io::Result<Vec<u8>> {
        //let mut buffer = Vec::new();
        //self.conn.read_to_end(&mut buffer)?;
        //Ok(buffer)
    //}
    pub fn receive_data(&mut self) -> Vec<u8> {
        let record = format::read_record(&mut self.conn);
        println!("gotten record is : {:?}", &record.0);
        let mut iv = self.keys.server_application_iv.clone();
        iv[11] ^= self.records_received;
        let plaintext = decrypt(&self.keys.server_application_key, &iv, &record.0[..]);
        println!("decrypted record is : {:?}", &plaintext);
        self.records_received +=1;
        plaintext
    }

    //pub fn receive_http_response(&mut self) -> io::Result<Vec<u8>> {
        //self.receive_data()
    //}

    pub fn receive_http_response(&mut self) -> Vec<u8> {
        //
        let mut response = Vec::new();

        loop {
            println!("receive a portion!");
            let pt = self.receive_http_data();
            println!("pt is : {:?}", pt);
            response.extend_from_slice(&pt);

            // Проверяем, совпадает ли конец ответа с искомой последовательностью
            if pt.len() >= 5 && &pt[pt.len() - 5..] == &[0x0D, 0x0A, 0x0D, 0x0A, 0x17] {
                break;
            }
        }

        response
    }

    fn receive_http_data(&mut self) -> Vec<u8> {
        let record = format::read_record(&mut self.conn); // Предполагаем, что read_record реализован
        let mut iv = vec![0u8; 12]; // IV длиной 12 байт

        // Копируем вектор server_application_iv в iv
        iv.copy_from_slice(&self.keys.server_application_iv);

        // Изменяем последний байт iv
        iv[11] ^= self.records_received as u8;

        // Расшифровка данных
        let plaintext = decrypt(&self.keys.server_application_key, &iv.try_into().unwrap(), &record.0[..]);

        // Увеличиваем количество полученных записей
        self.records_received += 1;

        plaintext
    }

    pub fn encrypt_application_data(&mut self, data: &[u8]) -> Vec<u8> {
        let mut data_vec = data.to_vec();
        data_vec.push(0x17);
        let additional_length = (data.len() + 16) as u16;
        let additional = format::concatenate(&[
            &[0x17, 0x03, 0x03], &format::u16_to_bytes(additional_length)
        ]);
        encrypt(&self.keys.client_application_key, &self.keys.client_application_iv, &data_vec[..], &additional[..])
    }

    pub fn client_hello(name: &str, keys: &Keys) -> Vec<u8> {
        let extensions = format::concatenate(&[
            &format::extension(0x0, format::server_name(name)), // SNI extension
            &format::extension(0x0a, vec![0x00, 0x02, 0x00, 0x1d]), // groups
            &format::extension(0x0d, vec![
                0x00, 0x12, 0x04, 0x03,
                0x08, 0x04, 0x04, 0x01,
                0x05, 0x03, 0x08, 0x05,
                0x05, 0x01, 0x08, 0x06,
                0x06, 0x01, 0x02, 0x01
            ]), // Signature algorithms
            &format::extension(0x33, format::key_share(&keys.public)), // Key share
            &format::extension(0x2d, vec![0x01, 0x01]), // PSK (no effect)
            &format::extension(0x2b, vec![0x02, 0x03, 0x04]) // TLS version
        ]
        );

        let handshake = format::concatenate( &[
            &[0x03, 0x03], // Client version: TLS 1.2
            &random32bytes(),   // Client random
            &[0x00],       // No session id
            &[0x00, 0x02, 0x13, 0x01], // Cipher suites: TLS_AES_128_GCM_SHA256
            &[0x01, 0x00], // Cipher suite length
            &format::u16_to_bytes(extensions.len() as u16), // Extensions length
            &extensions] // Extensions
        );

        format::concatenate( &[
            &[0x16, 0x03, 0x01], // Handshake
            &format::u16_to_bytes((handshake.len() + 4) as u16), // Length of handshake
            &[0x01, 0x00], // Handshake type
            &format::u16_to_bytes(handshake.len() as u16), // Handshake length
            &handshake] // Handshake
        )
    }
}

