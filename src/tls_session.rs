//mod tls_format;
mod aes256gcm;
mod certs;
mod hkdf_sha256;
mod x25519;

use x25519::curve25519_donna;
use format::*;
use network::send;
use hkdf_sha256::*;
use certs::check_certs;

use std::io::{self, Write};
use std::net::TcpStream;
use std::ops::Mul;

//use base64::decode;
use base64url::decode;
use hex::FromHex;

use rand::{RngCore, thread_rng};
use crate::{network, format};
use crate::tls_session::certs::{check_certs_with_fixed_root, check_certs_with_known_roots}; // Для генерации случайных данных

use std::fs::File;

//const UnknownSignatureAlgorithm: u16 = 0;
//const MD2WithRSA: u16 = 1;  // Unsupported.
//const MD5WithRSA: u16 = 2;  // Only supported for signing, not verification.
//const SHA1WithRSA: u16 = 3; // Only supported for signing, and verification of CRLs, CSRs, and OCSP responses.
const SHA256WITH_RSAE: u16 = 2052; // 08 04 (RSA-PSS-RSAE-SHA256)
const SHA384WITH_RSAE: u16 = 2053; // 08 05 (RSA-PSS-RSAE-SHA384)
const SHA512WITH_RSAE: u16 = 2054; // 08 06 (RSA-PSS-RSAE-SHA512)

const SHA256WITH_RSA: u16 = 1025; // 04 01 (RSA-PKCS1-SHA256)
const SHA384WITH_RSA: u16 = 1281; // 05 01 (RSA-PKCS1-SHA384)
const SHA512WITH_RSA: u16 = 1537; // 06 01 (RSA-PKCS1-SHA512)
//const DSAWithSHA1: u16 = 7;   // Unsupported.
//const DSAWithSHA256: u16 = 8; // Unsupported.
//const ECDSAWithSHA1: u16 = 9; // 03 03 () Only supported for signing, and verification of CRLs, CSRs, and OCSP responses.
const ECDSA_WITH_SHA256: u16 = 1027; // 04 03 (ECDSA-SECP256r1-SHA256)
const ECDSA_WITH_SHA384: u16 = 1283; // 05 03 (ECDSA-SECP384r1-SHA384)
const ECDSA_WITH_SHA512: u16 = 1539; // 06 03 (ECDSA-SECP521r1-SHA512)
const SHA256WITH_RSAPSS: u16 = 2057; // 08 09 (RSA-PSS-PSS-SHA256)
const SHA384WITH_RSAPSS: u16 = 2058; // 08 0a (RSA-PSS-PSS-SHA384)
const SHA512WITH_RSAPSS: u16 = 2059; // 08 0b (RSA-PSS-PSS-SHA512)
const PureEd25519: u16 = 2055; // 08 07 (ED25519)

pub fn get_root_cert_google_g1() -> [u8;1371] {
    certs::ROOT_GOOGLE_CERT_G1
}

pub fn get_root_cert_google_g2() -> [u8;1371] {
    certs::ROOT_GOOGLE_CERT_G2
}

pub fn get_root_cert_google_g3() -> [u8;525] {
    certs::ROOT_GOOGLE_CERT_G3
}

pub fn get_root_cert_google_g4() -> [u8;525] {
    certs::ROOT_GOOGLE_CERT_G4
}

pub fn get_root_cert_kakao() -> [u8;914] {
    certs::ROOT_KAKAO_CERT
}

pub fn get_root_cert_facebook() -> [u8;969] {
    certs::ROOT_FACEBOOK_CERT
}

pub struct Keys {
    pub public: [u8; 32],
    pub private: [u8; 32],//Vec<u8>,
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
    //println!("private_key {:?}", private_key);
    //println!("public_key {:?}", public_key);

    Keys {
        public: public_key, // public_key.compress().to_bytes().to_vec(),
        private: private_key,
        //server_public: Vec::new(),
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
    return plaintext;
}

fn encrypt(key: &[u8;16], iv: &[u8;12], plaintext: &[u8], additional: &[u8]) -> Vec<u8> {
    let block = aes256gcm::new_cipher(key);
    let aes_gcm = aes256gcm::new_gcm(block);

    //let nonce = Nonce::from_slice(iv); // 96-bits; retrieve nonce from the IV
    //let ciphertext = aesgcm.encrypt(nonce, additional, plaintext).expect("Encryption failed");
    let ciphertext = aes_gcm.seal(&[], iv, plaintext, additional);

    [additional.to_vec(), ciphertext].concat() // Concatenate additional data with ciphertext
}

pub fn hkdf_expand_label(secret: &[u8;32], label: &str, context: &[u8], length: u16) -> Vec<u8> {
    // Construct HKDF label
    let mut hkdf_label = vec![];
    hkdf_label.extend_from_slice(&length.to_be_bytes());
    let tls13_prefix = b"tls13 ";
    hkdf_label.push((tls13_prefix.len()+label.as_bytes().len()) as u8);
    hkdf_label.extend_from_slice(tls13_prefix);
    hkdf_label.extend_from_slice(label.as_bytes());

    hkdf_label.push(context.len() as u8);
    hkdf_label.extend_from_slice(context);

    //println!("hkdf_label is : {:?}", hkdf_label);
    //println!("secret is : {:?}", &secret);

    // Expand using HKDF
    let mut reader = hkdf_sha256::expand(secret, &hkdf_label[..]);//let hkdf = Hkdf::<Sha256>::new(Some(secret), &hkdf_label);
    let buf = reader.read(length as usize);
    //println!("hkdf expand result is is : {:?}", &buf);

    buf
}

pub fn derive_secret(secret: &[u8;32], label: &str, transcript_messages: &[u8]) -> [u8; 32] {

    let hash = hkdf_sha256::sum256( transcript_messages);
    //println!("derive_secret hash is : {:?}", &hash);
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
            messages: Messages{client_hello: Record::new(), server_hello: Record::new(), server_handshake: DecryptedRecord::new(),
                encrypted_server_handshake: Record::new(), application_request: Record::new(), encrypted_ticket: Record::new(), http_response: Record::new()},
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

    }

    fn parse_server_handshake(&mut self) -> bool{

        // ignore change cipher spec 14 03 03
        let mut record = format::read_record(&mut self.conn); // let record = tls_format::ReadRecord(&self.conn);
        if record.rtype() == 0x14 {
            //println!("pass change cipher spec")
            record = format::read_record(&mut self.conn);
        }

        if record.rtype() != 0x17 {
            //panic!("expected wrapper (ParseServerHandshake)");
            println!("expected wrapper (ParseServerHandshake)");
            return false;
        }
        let mut server_handshake_message = decrypt(&self.keys.server_handshake_key, &self.keys.server_handshake_iv, &record.0[..]);
        //println!("server_handshake_message is : {:?}", &server_handshake_message);
        if server_handshake_message.len()>2000 {
            self.messages.encrypted_server_handshake = record.clone();
        } else {
            server_handshake_message = format::trunc_end_22(&server_handshake_message);//server_handshake_message.pop();
            println!("server_handshake_message is : {:?}", &server_handshake_message);
            //server_handshake_message = [8u8, 0u8, 0u8, 2u8, 0u8, 0u8].to_vec();
            let mut records_received_counter = 1u8;

            loop {
                let record = format::read_record(&mut self.conn);
                let mut iv = self.keys.server_handshake_iv.clone();
                iv[11] ^= records_received_counter;
                let mut server_handshake_message_next_part = decrypt(&self.keys.server_handshake_key, &iv, &record.0[..]);
                server_handshake_message_next_part = format::trunc_end_22(&server_handshake_message_next_part);//server_handshake_message_next_part.pop();
                println!("server_handshake_message_next_part is : {:?}", &server_handshake_message_next_part);
                //let message_type = server_handshake_message_next_part[0];
                let handshake_finish = format::contains_handshake_finish(&server_handshake_message_next_part);
                server_handshake_message.append(&mut server_handshake_message_next_part);
                records_received_counter += 1;

                //println!("message_type is : {:?}", &message_type);
                if handshake_finish { // if message_type==0x14 {
                    break;
                }
            }
            server_handshake_message.push(22u8);

            let server_handshake_message_len = server_handshake_message.len() + 16;
            let server_handhake_len_bytes = format::u16_to_bytes(server_handshake_message_len as u16);
            let mut header = [23u8, 3u8, 3u8, 0u8, 0u8];
            header[3] = server_handhake_len_bytes[0];
            header[4] = server_handhake_len_bytes[1];
            let encrypted_overall_record = encrypt(&self.keys.server_handshake_key, &self.keys.server_handshake_iv, &server_handshake_message, &header);
            self.messages.encrypted_server_handshake = Record{0: encrypted_overall_record};
        }
        self.messages.server_handshake = DecryptedRecord{ 0: server_handshake_message};

        self.make_application_keys();
        if !(self.check_handshake()){
            return false;
        }
        return true;
    }

    pub fn check_handshake(&mut self) -> bool {
        let handshake_data = self.messages.server_handshake.contents();
        println!("check_handshake handshake_data is : {:?}", &handshake_data);
        let len_of_padding = handshake_data[3] as usize;
        let certs_chain = &handshake_data[4+len_of_padding+1..];//let certs_chain = &handshake_data[7..];

        //println!("check_handshake certs_chain is : {:?}", &certs_chain);

        //next three bytes is the length of certs chain
        let certs_chain_len = (certs_chain[0] as usize)*65536 + (certs_chain[1] as usize)*256 + (certs_chain[2] as usize);
        println!("certs_chain_len is : {:?}", &certs_chain_len); // must be 4205 = 4096 + 109
        if certs_chain[certs_chain_len + 3] != 0xf {
            panic!("signature not found");
        }

        let sign_type = (certs_chain[certs_chain_len + 7] as u16)*256 + (certs_chain[certs_chain_len + 8] as u16);
        if sign_type!=SHA256WITH_RSAE && sign_type!=SHA256WITH_RSA && sign_type!=ECDSA_WITH_SHA256 && sign_type!=SHA256WITH_RSAPSS {
            panic!("not supported (not sha256) type of signature");
        }

        let signature_len = (certs_chain[certs_chain_len + 9] as usize)*256 + (certs_chain[certs_chain_len + 10] as usize);
        println!("signature_len is : {:?}", &signature_len);
        let signature = &certs_chain[certs_chain_len + 11..certs_chain_len + 11 + signature_len];

        let current_timestamp = 1000i64;// SystemTime::now()

        let client_server_hello = format::concatenate(&[self.messages.client_hello.contents(), self.messages.server_hello.contents()]);
        let check_sum = hkdf_sha256::sum256(&client_server_hello);
        let check_result = check_certs_with_known_roots(current_timestamp,
                        &check_sum,
                        &certs_chain[4..certs_chain_len+1],
                        &signature);
        if check_result.is_none() {
            //panic(err.Error())
            println!("error in certificates chain !");
            return false;
        }
        //write to file
        let mut file = File::create("found_root_id.txt").expect("Error creating file");
        file.write(check_result.unwrap().to_string().as_bytes());
        return true;
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

        //self.server_hello.public_key=[246, 48, 130, 234, 125, 96, 179, 219, 52, 226, 168, 235, 57, 47, 53, 103, 96, 246, 129, 101, 202, 83, 142, 117, 64, 20, 47, 242, 241, 212, 56, 30];
        //println!("&self.server_hello.public_key is : {:?}", &self.server_hello.public_key);
        let shared_secret = curve25519_donna(&self.keys.private, &self.server_hello.public_key); //let shared_secret = X25519::from_slice(&self.keys.private).mul(&self.server_hello.public_key);
        //println!("shared_secret is : {:?}", shared_secret);

        // Хэндшейк с использованием HKDF
        let early_secret = hkdf_sha256::extract(&zeros,&psk); //let (early_secret, hkdf) = Hkdf::<Sha256>::extract(Some(&zeros), &psk);
        let derived_secret = derive_secret(&early_secret, "derived", &[]);
        //println!("derived_secret is : {:?}", derived_secret);
        self.keys.handshake_secret = hkdf_sha256::extract(&shared_secret, &derived_secret);//self.keys.handshake_secret = Hkdf::<Sha256>::extract(Some(&shared_secret), &derived_secret);
        //println!("self.keys.handshake_secret is : {:?}", self.keys.handshake_secret);

        let handshake_messages = format::concatenate(
            &[&self.messages.client_hello.contents(),
            &self.messages.server_hello.contents()]
        );
        //println!("handshake_messages is : {:?}", handshake_messages);
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

        println!("send_data msg is : {:?}", msg);
        self.records_sent +=1;
        self.conn.write(&msg[..]);// self.conn.write_all(data)?;
        self.messages.application_request = Record{0:msg};
    }

    pub fn receive_data(&mut self) -> Vec<u8> { // receive ticket
        let record = format::read_record(&mut self.conn);
        println!("gotten record is : {:?}", &record.0);
        let mut iv = self.keys.server_application_iv.clone();
        iv[11] ^= self.records_received;
        println!("receive_data iv is : {:?}", &iv);
        println!("receive_data self.keys.server_application_key is : {:?}", &self.keys.server_application_key);
        let plaintext = decrypt(&self.keys.server_application_key, &iv, &record.0[..]);
        println!("decrypted record is : {:?}", &plaintext);
        self.records_received +=1;
        self.messages.encrypted_ticket = record;
        plaintext
    }

    pub fn receive_http_response(&mut self) -> Vec<u8> {
        //
        let mut response = Vec::new();

        loop {
            println!("receive a portion!");
            let mut pt = self.receive_http_data();
            pt = format::trunc_end_23(&pt);
            println!("pt is : {:?}", pt);
            response.extend_from_slice(&pt[..pt.len()]); // response.extend_from_slice(&pt[..pt.len()-1]);
            //response.push(23);

            // Проверяем, совпадает ли конец ответа с искомой последовательностью
            if pt.len() >= 5 && &pt[pt.len() - 4..] == &[0x0D, 0x0A, 0x0D, 0x0A] { // if pt.len() >= 5 && &pt[pt.len() - 5..] == &[0x0D, 0x0A, 0x0D, 0x0A, 0x17] {
                break;
            }
        }

        response
    }

    fn receive_http_data(&mut self) -> Vec<u8> {
        let record = format::read_record(&mut self.conn); // Предполагаем, что read_record реализован
        let mut iv = vec![0u8; 12]; // IV длиной 12 байт

        println!("receive_http_data record is : {:?}", &record.0[..]);
        // Копируем вектор server_application_iv в iv
        iv.copy_from_slice(&self.keys.server_application_iv);

        // Изменяем последний байт iv
        iv[11] ^= self.records_received as u8;

        // Расшифровка данных
        let plaintext = decrypt(&self.keys.server_application_key, &iv.try_into().unwrap(), &record.0[..]);
        println!("receive_http_data plaintext is : {:?}", &plaintext);

        // Увеличиваем количество полученных записей
        self.records_received += 1;

        self.messages.http_response.0.extend(record.0);// add to sequence of ciphertexts

        plaintext
    }

    pub fn encrypt_application_data(&mut self, data: &[u8]) -> Vec<u8> {
        let mut data_vec = data.to_vec();
        println!("encrypt_application_data data.len() is : {:?}", &data.len());
        data_vec.push(0x17);
        let additional_length = (data_vec.len() + 16) as u16;
        let additional = format::concatenate(&[
            &[0x17, 0x03, 0x03], &format::u16_to_bytes(additional_length)
        ]);
        println!("encrypt_application_data additional is : {:?}", &additional);
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

    pub fn serialize(&mut self) -> Vec<u8> {
        let mut res = self.keys.private.to_vec();
        res.push(self.records_sent);// messages sent
        res.push(self.records_received);// messages received
        res.extend(&self.messages.client_hello.0); // send client hello
        res.extend(&self.messages.server_hello.0); // get server hello
        // may be add change cipher spec 14 03 03 ...
        res.extend(&self.messages.encrypted_server_handshake.0); // server handshake message
        //res.extend(&self.messages.server_handshake); // server handshake message (decrypted)
        res.extend(&self.messages.application_request.0);
        res.extend(&self.messages.encrypted_ticket.0);
        res.extend(&self.messages.http_response.0);

        res
    }


}

pub fn extract_json_public_key_from_tls(raw: Vec<u8>) -> Vec<u8> {
    let timestamp_bytes = &raw[..4];
    let len_of_kid = raw[4] as usize;
    let kid = &raw[5..5 + len_of_kid]; // let kid = &raw[4..24];
    let start_cert = 5 + len_of_kid;
    let certificate_len = (256*raw[start_cert] as u16 + raw[start_cert+1] as u16) as usize; // let certificate_len = (256*raw[24] as u16 + raw[25] as u16) as usize;
    println!("certificate_len is : {:?}", &certificate_len);

    let external_root_cert = &raw[start_cert+2..start_cert+2+certificate_len]; // let external_root_cert = &raw[26..26+certificate_len];
    let data = &raw[start_cert+2+certificate_len..]; // let data = &raw[26+certificate_len..];

    // the first output byte indicates the success of the process: if it equals to 1 then success
    // then follows the public keys from json
    // if the first bytes equals to 0 then unsuccess and the error code follows
    let timestamp_shortened = aes256gcm::uint32(&timestamp_bytes);
    let timestamp = timestamp_shortened as i64;
    let private_key:[u8;32] = data[0..32].try_into().unwrap();
    println!("private_key is : {:?}", &private_key);
    let records_send: u8 = data[32];
    let records_received_declared: u8 = data[33];
    // check len of data
    println!("data.len() is : {:?}", &data.len());
    if data.len()<5000{ // 6500
        return vec![0u8, 3u8, 33u8]; // "insufficient len" : 0x3, 0x21 = 801
    }
    let client_hello_len = data[38] as usize;
    println!("client_hello_len is : {:?}", &client_hello_len);
    let client_hello: &[u8] = &data[34..39+client_hello_len]; //let client_hello:[u8;166] = data[34..200].try_into().unwrap(); // len is 166 bytes
    println!("client_hello is : {:?}", &client_hello);
    if client_hello[0] != 0x16 {
        return vec![0u8, 3u8, 34u8]; // "client hello not found"
    }
    let server_hello_start = 39+client_hello_len;
    let server_hello:[u8;95] = data[server_hello_start..server_hello_start+95].try_into().unwrap();//let server_hello:[u8;95] = data[200..295].try_into().unwrap(); // len is 95 bytes
    println!("server_hello is : {:?}", &server_hello);
    if server_hello[0] != 0x16 {
        println!(" server hello not found");
        return vec![0u8, 3u8, 35u8]; // "server hello not found"
    }
    let enc_ser_handshake_len = 256*data[server_hello_start+98] as u16 + data[server_hello_start+99] as u16; // let enc_ser_handshake_len = 256*data[298] as u16 + data[299] as u16;
    println!("enc_ser_handshake_len is : {:?}", &enc_ser_handshake_len);// 16*256 + 249 = 4345
    let handshake_end_index = server_hello_start + 95 + 5 + enc_ser_handshake_len as usize; // let handshake_end_index = 295 + 5 + enc_ser_handshake_len as usize;
    println!("handshake_end_index is : {:?}", &handshake_end_index);

    // let encrypted_server_handshake:[u8;4350] = data[295..handshake_end_index].try_into().unwrap();
    let encrypted_server_handshake = &data[server_hello_start + 95..handshake_end_index]; // let encrypted_server_handshake = &data[295..handshake_end_index];
    println!("encrypted_server_handshake is : {:?}", &encrypted_server_handshake);

    let app_request_len = 256*data[handshake_end_index+3] as usize + data[handshake_end_index+4] as usize + 5;
    //println!("app_request_len is : {:?}", &app_request_len);
    let application_request = &data[handshake_end_index..handshake_end_index + app_request_len]; // let application_request:[u8;100] = data[handshake_end_index..handshake_end_index+100].try_into().unwrap();
    println!("application_request is : {:?}", &application_request);

    let mut records_received: u8 = 1;
    let mut encr_ticket_len = 256*data[handshake_end_index + app_request_len + 3] as usize + data[handshake_end_index + app_request_len+4] as usize +5;
    println!("encr_ticket_len is : {:?}", &encr_ticket_len);
    if encr_ticket_len ==241 { // if encr_ticket_len < 300 {
        encr_ticket_len = encr_ticket_len*2;
        records_received = 2;
    }

    let encrypted_ticket: &[u8] = &data[handshake_end_index + app_request_len..handshake_end_index + app_request_len + encr_ticket_len];// let encrypted_ticket: &[u8] = &data[handshake_end_index + app_request_len..handshake_end_index + app_request_len +540];// let encrypted_ticket:[u8;540] = data[handshake_end_index+100..handshake_end_index+100+540].try_into().unwrap(); // len of ticket is 524
    println!("encrypted_ticket is : {:?}", &encrypted_ticket);

    //let http_response:[u8;1601] = data[handshake_end_index+640..handshake_end_index+640+1601].try_into().unwrap();
    let http_response = &data[handshake_end_index + app_request_len + encr_ticket_len..]; // let http_response = &data[handshake_end_index + app_request_len + 540..]; // let http_response = &data[handshake_end_index+640..];
    println!("encrypted http_response is : {:?}", &http_response);

    let basepoint:[u8;32] = [9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let public_key = curve25519_donna(&private_key, &basepoint);
    println!("public_key is : {:?}", &public_key);

    println!("records send is : {:?}", records_send);
    println!("records received is : {:?}", records_received);

    let server_hello_data = parse_server_hello(&server_hello[5..]);

    // ================== begin make handshake keys ===============================================================================================
    let zeros = [0u8; 32];
    let psk = [0u8; 32]; // Предполагается, что psk инициализируется где-то

    let shared_secret = curve25519_donna(&private_key, &server_hello_data.public_key);
    println!("shared_secret is : {:?}", shared_secret);

    // Хэндшейк с использованием HKDF
    let early_secret = hkdf_sha256::extract(&zeros,&psk);

    println!("early_secret is : {:?}", early_secret);
    let derived_secret = derive_secret(&early_secret, "derived", &[]);
    println!("derived_secret is : {:?}", derived_secret);

    let handshake_secret = hkdf_sha256::extract(&shared_secret, &derived_secret);
    println!("self.keys.handshake_secret is : {:?}", handshake_secret);

    let handshake_messages = format::concatenate(
            &[&client_hello[5..], &server_hello[5..] ]
    );
    println!("handshake_messages is : {:?}", handshake_messages);

    let c_hs_secret = derive_secret(&handshake_secret, "c hs traffic", &handshake_messages);
    let client_handshake_secret = c_hs_secret.clone();
    let client_handshake_key: [u8;16] = hkdf_expand_label(&c_hs_secret, "key", &[], 16).try_into().unwrap();
    //println!("self.keys.client_handshake_key is : {:?}", self.keys.client_handshake_key);
    let client_handshake_iv: [u8;12] = hkdf_expand_label(&c_hs_secret, "iv", &[], 12).try_into().unwrap();
    //println!("self.keys.client_handshake_iv is : {:?}", self.keys.client_handshake_iv);

    let s_hs_secret = derive_secret(&handshake_secret, "s hs traffic", &handshake_messages);
    //let session_keys_server_handshake_key = hkdf_expand_label(&s_hs_secret, "key", &[], 16);
    //println!("session_keys_server_handshake_key_ is : {:?}", &session_keys_server_handshake_key);
    println!("s_hs_secret is : {:?}", s_hs_secret);
    let server_handshake_key: [u8;16] = hkdf_expand_label(&s_hs_secret, "key", &[], 16).try_into().unwrap();
    let server_handshake_iv: [u8;12] = hkdf_expand_label(&s_hs_secret, "iv", &[], 12).try_into().unwrap();

    // ============== begin parse server handshake =====================
    if encrypted_server_handshake[0] != 0x17 {
        return vec![0u8, 3u8, 36u8];// "not found encrypted server handshake"
    }

    let server_handshake_message = decrypt(&server_handshake_key, &server_handshake_iv, &encrypted_server_handshake[..]);
    println!("server_handshake_message is : {:?}", &server_handshake_message);
    let decrypted_server_handshake = DecryptedRecord{ 0: server_handshake_message};

    // ============= begin make application keys ===================================
    let handshake_messages = format::concatenate( &[
        &client_hello[5..],
        &server_hello[5..],
        &decrypted_server_handshake.contents()]
    );

    let derived_secret = derive_secret(&handshake_secret, "derived", &[]);
    let master_secret = hkdf_sha256::extract(&zeros, &derived_secret);//let master_secret = Hkdf::<Sha256>::extract(Some(&zeros), &derived_secret);

    let c_ap_secret = derive_secret(&master_secret, "c ap traffic", &handshake_messages);
    let client_application_key: [u8;16] = hkdf_expand_label(&c_ap_secret, "key", &[], 16).try_into().unwrap();
    let client_application_iv: [u8;12] = hkdf_expand_label(&c_ap_secret, "iv", &[], 12).try_into().unwrap();

    let s_ap_secret = derive_secret(&master_secret, "s ap traffic", &handshake_messages);
    let server_application_key: [u8;16] = hkdf_expand_label(&s_ap_secret, "key", &[], 16).try_into().unwrap();
    let server_application_iv: [u8;12] = hkdf_expand_label(&s_ap_secret, "iv", &[], 12).try_into().unwrap();

    // ========== begin check handshake ================
    let handshake_data = decrypted_server_handshake.contents();//[5..];
    //let certs_chain = &handshake_data[7..];
    let len_of_padding = handshake_data[3] as usize;
    let certs_chain = &handshake_data[4+len_of_padding+1..];

    //next three bytes is the length of certs chain
    let certs_chain_len = (certs_chain[0] as usize)*65536 + (certs_chain[1] as usize)*256 + (certs_chain[2] as usize);
    println!("certs_chain is : {:?}", &certs_chain);
    println!("certs_chain_len is : {:?}", &certs_chain_len); // must be 4205 = 4096 + 109

    if certs_chain[certs_chain_len + 3] != 0xf {
        return vec![0u8, 3u8, 37u8];// "signature not found"
    }

    let sign_type = (certs_chain[certs_chain_len + 7] as u16)*256 + (certs_chain[certs_chain_len + 8] as u16);

    let signature_len = (certs_chain[certs_chain_len + 9] as usize)*256 + (certs_chain[certs_chain_len + 10] as usize);
    let signature = &certs_chain[certs_chain_len + 11..certs_chain_len + 11 + signature_len];

    let client_server_hello = format::concatenate(&[&client_hello[5..], &server_hello[5..]]);
    if sign_type!=SHA256WITH_RSAE && sign_type!=SHA256WITH_RSA && sign_type!=ECDSA_WITH_SHA256 && sign_type!=SHA256WITH_RSAPSS {
        return vec![0u8, 3u8, 38u8];// "not supported (not sha256) type of signature"
    }
    let check_sum = hkdf_sha256::sum256(&client_server_hello);

    if !check_certs_with_fixed_root(timestamp, &check_sum, &certs_chain[4..certs_chain_len+1], &signature, &external_root_cert) {
        return vec![0u8, 3u8, 39u8]; // "error in certificates chain !"
    }

    // =================== begin check application request ===================
    /*let domain = "www.googleapis.com";
    let etalon_req = format!("GET /oauth2/v3/certs HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n", domain);
    let etalon_req_bytes = etalon_req.as_bytes();
    //encrypt etalon application request
    let mut data_vec = etalon_req_bytes.to_vec();
    data_vec.push(0x17);
    let additional_length = (data_vec.len() + 16) as u16;
    let additional = format::concatenate(&[
        &[0x17, 0x03, 0x03], &format::u16_to_bytes(additional_length)
    ]);
    let etalon_encrypted = encrypt(&client_application_key, &client_application_iv, &data_vec[..], &additional[..]);
    // match with application_request
    if application_request.to_vec() != etalon_encrypted {
        return vec![0u8, 3u8, 40u8]; // "incorrect application request !"
    }*/

    // =================== begin decryption ticket and check =========================

    // =================== begin decryption application response =====================
    //let ciphertext = [0x17, 0x03, 0x03, 0x05, 0x5f, 0x62, 0x1f, 0xf7, 0x3b, 0x44, 0xea, 0x1b, 0xe2, 0xde, 0x06, 0x26, 0x45, 0xcb, 0xa5, 0x3d, 0xed, 0x43, 0xd3, 0x59, 0xe5, 0x33, 0x7a, 0x81, 0x2a, 0x9d, 0x3a, 0x16, 0x54, 0x73, 0x14, 0x07, 0x77, 0xf9, 0xa1, 0x23, 0x34, 0x80, 0xfa, 0xb3, 0x04, 0x2a, 0xe3, 0x06, 0xaa, 0xa1, 0x30, 0x31, 0x0a, 0x3e, 0x96, 0x7e, 0xa0, 0x38, 0xa2, 0xc2, 0xfd, 0x6e, 0xb8, 0xcd, 0x63, 0xbd, 0xe6, 0x49, 0x74, 0x2d, 0x1c, 0x0d, 0xeb, 0x96, 0xf1, 0xce, 0x52, 0x3a, 0xfd, 0xb7, 0xcc, 0xed, 0x49, 0xad, 0xd9, 0x64, 0xa2, 0x62, 0x06, 0x19, 0x69, 0x72, 0xa3, 0xd2, 0x68, 0x96, 0xa8, 0x0b, 0x5f, 0xb7, 0x68, 0x62, 0x9d, 0xdc, 0xb2, 0xa0, 0x28, 0x62, 0x25, 0x03, 0x56, 0x89, 0x81, 0x55, 0xa4, 0xf8, 0x2d, 0xea, 0xcd, 0x03, 0x10, 0x4e, 0xdd, 0xed, 0x14, 0x80, 0x02, 0x13, 0x38, 0x40, 0xb3, 0xa2, 0x1e, 0x98, 0x9b, 0xb0, 0x17, 0x93, 0x08, 0x21, 0x42, 0xce, 0xb7, 0x56, 0xa4, 0x3c, 0x18, 0x98, 0x4d, 0x0a, 0x10, 0x2d, 0xc1, 0xc2, 0x05, 0xde, 0x09, 0xb1, 0x46, 0xa7, 0x06, 0x99, 0x3c, 0x7f, 0xa7, 0x57, 0xbb, 0x97, 0x00, 0x40, 0x33, 0x72, 0x77, 0x85, 0x3e, 0xb6, 0x9e, 0xfe, 0x24, 0x91, 0x60, 0xb8, 0x51, 0x63, 0x00, 0x8e, 0x0d, 0xfb, 0x3d, 0x31, 0x44, 0xba, 0x68, 0x23, 0x1c, 0x81, 0x1c, 0xb7, 0x67, 0x36, 0x00, 0x3d, 0x28, 0xf6, 0xe2, 0x11, 0xb3, 0xd5, 0xfe, 0xc1, 0xc6, 0x78, 0x50, 0x4e, 0x3d, 0x93, 0xc3, 0x1e, 0xda, 0xe1, 0x38, 0x29, 0x54, 0xca, 0xae, 0x44, 0x89, 0x08, 0x01, 0x10, 0x6f, 0x89, 0x94, 0x8c, 0x09, 0xe9, 0x61, 0xa2, 0x98, 0x92, 0x29, 0x49, 0x72, 0x80, 0xf6, 0x09, 0x8f, 0x64, 0x57, 0x4b, 0xdd, 0x2e, 0x25, 0x26, 0x9f, 0x7d, 0x40, 0x0f, 0x46, 0x0c, 0x6a, 0x29, 0x07, 0x35, 0x89, 0x71, 0xf4, 0xd1, 0xe4, 0x85, 0xc9, 0x41, 0xfa, 0x58, 0x08, 0x29, 0xeb, 0x38, 0xf4, 0x70, 0x6c, 0xff, 0x0f, 0xd4, 0x1f, 0x14, 0x99, 0xc6, 0xa1, 0x7a, 0xe0, 0xd6, 0x9b, 0xc0, 0x31, 0x29, 0x4a, 0xb7, 0x36, 0xfc, 0x7d, 0x7c, 0xe3, 0xa8, 0x71, 0x07, 0xe2, 0x48, 0x07, 0x40, 0x64, 0xa0, 0x83, 0xb5, 0x41, 0x80, 0x68, 0xb5, 0x1e, 0x74, 0x3f, 0x36, 0x79, 0x57, 0x29, 0x69, 0xe9, 0xb0, 0xa4, 0x6a, 0xbf, 0xd1, 0xf3, 0xbb, 0xa1, 0xda, 0x33, 0x6a, 0xe1, 0x27, 0x62, 0xbe, 0x2a, 0x2e, 0xb9, 0x01, 0xca, 0x43, 0x1c, 0x5b, 0x8f, 0xf1, 0x96, 0xcb, 0x7d, 0x0c, 0x97, 0x5d, 0xb1, 0xd1, 0x0c, 0x64, 0x74, 0xcd, 0x78, 0xb2, 0x6f, 0x02, 0x55, 0x9b, 0x6b, 0xc0, 0x0d, 0xe2, 0x9e, 0x98, 0x16, 0x5f, 0xcd, 0x51, 0xe7, 0xff, 0x9a, 0x6a, 0x9b, 0xd7, 0x9d, 0xdd, 0x78, 0xc3, 0xbf, 0xec, 0xc6, 0x9d, 0xee, 0xe9, 0x2f, 0x94, 0xf9, 0x2d, 0xe3, 0xd6, 0xb5, 0xc6, 0x5c, 0x7e, 0x18, 0x72, 0x74, 0x92, 0x25, 0xc6, 0xff, 0x53, 0x1d, 0xf2, 0x29, 0xc6, 0x30, 0x25, 0x4f, 0xc3, 0x5d, 0x3f, 0x76, 0xf6, 0x9d, 0xff, 0xdb, 0x6d, 0xa2, 0x49, 0x09, 0x88, 0xf8, 0x6d, 0xaf, 0xf4, 0x1e, 0x29, 0xc7, 0xc1, 0x6f, 0x57, 0x5e, 0x5c, 0x0e, 0x4f, 0x9d, 0x99, 0xa6, 0xdd, 0xf6, 0x49, 0xf0, 0xb8, 0x22, 0x55, 0x45, 0x81, 0x27, 0x0f, 0xde, 0x73, 0x79, 0x43, 0xed, 0x4d, 0x66, 0x81, 0xbe, 0x22, 0x8f, 0x87, 0x96, 0x60, 0xb0, 0x55, 0x8a, 0xcb, 0x24, 0x96, 0xbf, 0x1d, 0x85, 0x6f, 0x7c, 0xd7, 0xb2, 0xa4, 0xc7, 0xba, 0xe4, 0xb9, 0x6b, 0x74, 0x1f, 0xee, 0xec, 0xcc, 0x3e, 0x5e, 0xb4, 0xf6, 0xe3, 0xc6, 0x52, 0x5a, 0xe6, 0x97, 0x6d, 0x17, 0x41, 0xc2, 0xf2, 0x4b, 0x5f, 0xf5, 0x07, 0x9e, 0x87, 0x8f, 0xf2, 0xe2, 0xb5, 0x85, 0x09, 0x38, 0xcb, 0x28, 0x5f, 0x42, 0x2a, 0xd9, 0xb7, 0xac, 0x9d, 0xbc, 0x00, 0x6f, 0x9e, 0xa3, 0x5f, 0xbc, 0x80, 0xe3, 0xa4, 0x8d, 0x9d, 0xed, 0xa6, 0xa1, 0x17, 0xdd, 0x96, 0x4a, 0xb3, 0x24, 0x97, 0x02, 0x95, 0x35, 0xc2, 0x87, 0x61, 0xf4, 0x7c, 0x37, 0x1a, 0xa5, 0x6d, 0x2c, 0x09, 0x7b, 0xec, 0x7d, 0x70, 0x8c, 0x8f, 0xde, 0xd5, 0x3c, 0xe3, 0x36, 0xdb, 0x57, 0x68, 0xbe, 0x43, 0xd4, 0x6e, 0x1c, 0xed, 0x7a, 0xca, 0xe7, 0xc7, 0xf7, 0x46, 0x83, 0x48, 0x45, 0x5a, 0x82, 0xc8, 0x63, 0x23, 0xf3, 0x4c, 0xe8, 0x75, 0xa8, 0x07, 0x87, 0x4d, 0xc0, 0x1f, 0x73, 0x5d, 0xa7, 0xd7, 0xa7, 0xc0, 0x78, 0x9d, 0x4c, 0x45, 0xbe, 0xa4, 0x08, 0x02, 0x5e, 0x51, 0x20, 0x0e, 0x9e, 0xef, 0xb3, 0xb4, 0x0e, 0xdf, 0xac, 0x70, 0x1f, 0x88, 0xad, 0x95, 0xb5, 0xc1, 0x82, 0xf7, 0x64, 0xe1, 0xe8, 0x3a, 0x79, 0x37, 0x7a, 0x94, 0x98, 0xf1, 0xee, 0x5a, 0x7a, 0x59, 0x81, 0x3e, 0x4a, 0x2c, 0x4e, 0xbd, 0x9c, 0x98, 0x96, 0x6a, 0xe9, 0x65, 0x2c, 0x92, 0xfe, 0xc3, 0x30, 0xdc, 0x16, 0xee, 0x35, 0xc6, 0x10, 0xfa, 0x36, 0xe7, 0x6a, 0x52, 0xe1, 0x92, 0x64, 0x8b, 0x06, 0xd7, 0x69, 0xb9, 0xc5, 0x24, 0xb6, 0xba, 0xed, 0x97, 0x69, 0x8f, 0xa3, 0xa5, 0xc3, 0xfd, 0x5a, 0x09, 0x7f, 0xa4, 0x6e, 0x7e, 0xfd, 0xec, 0xcf, 0xd3, 0x04, 0x9f, 0xe5, 0x54, 0xc7, 0x74, 0xf0, 0x53, 0xde, 0xc0, 0x65, 0x1d, 0x7b, 0xb1, 0x61, 0x10, 0xda, 0x06, 0x77, 0x30, 0x52, 0x5e, 0x48, 0x9b, 0x13, 0x3f, 0x13, 0x2a, 0x98, 0xc8, 0xc8, 0x3e, 0x7e, 0xdc, 0x84, 0xad, 0xa5, 0xb5, 0x47, 0x91, 0x24, 0xe4, 0x1a, 0x5c, 0xb0, 0x24, 0x65, 0x12, 0x61, 0x76, 0x8b, 0xb1, 0xb1, 0xfe, 0x4a, 0xbb, 0x24, 0xfb, 0x17, 0x18, 0xbe, 0x5e, 0x6c, 0x4b, 0x27, 0x92, 0x7e, 0xe9, 0x77, 0x5a, 0x0b, 0x55, 0xc1, 0xb4, 0xca, 0x8f, 0x66, 0x92, 0xec, 0xa5, 0x8f, 0x13, 0x0a, 0xb7, 0x6d, 0xe6, 0x6b, 0x55, 0xca, 0x4a, 0xad, 0x36, 0x3a, 0xfb, 0xfc, 0x0f, 0xbf, 0x19, 0xd4, 0xb3, 0xa7, 0x64, 0x35, 0x04, 0x43, 0x70, 0xbd, 0x30, 0x28, 0xe9, 0x60, 0xe8, 0x33, 0xd5, 0xf5, 0x22, 0x67, 0x30, 0x0e, 0xcf, 0x41, 0xe2, 0x27, 0xbe, 0x96, 0x1f, 0x27, 0x8b, 0x9f, 0x3e, 0x8d, 0x72, 0xf2, 0xfc, 0x3f, 0xd9, 0xd8, 0x18, 0x72, 0xf6, 0x97, 0xd7, 0x31, 0xc5, 0x52, 0x8b, 0x1f, 0x57, 0x33, 0xf3, 0x81, 0xbe, 0xab, 0x2c, 0x0c, 0x4a, 0x8d, 0x60, 0x82, 0xa1, 0xdf, 0x40, 0x0f, 0x97, 0xb3, 0xf5, 0x60, 0xea, 0x18, 0xa6, 0x8f, 0x77, 0xac, 0x02, 0x8b, 0xf2, 0x74, 0x74, 0x74, 0x57, 0x38, 0x2a, 0x3a, 0xa2, 0x07, 0xbe, 0x16, 0x59, 0x6f, 0x70, 0x22, 0x38, 0x57, 0xb2, 0xf3, 0xd7, 0x70, 0xb6, 0xeb, 0x88, 0x67, 0x9f, 0x3d, 0x69, 0xbf, 0x43, 0xc5, 0x46, 0x1b, 0xed, 0xf0, 0x30, 0x59, 0x59, 0x85, 0xab, 0x7d, 0x6c, 0x53, 0xa7, 0xa3, 0x6f, 0x72, 0xe6, 0xb9, 0xf8, 0x39, 0x31, 0x62, 0x17, 0x53, 0xa7, 0xc8, 0x26, 0xf1, 0xc2, 0x37, 0xd3, 0x6b, 0x80, 0xbc, 0xc4, 0xe3, 0x8a, 0x8c, 0xcb, 0x03, 0x35, 0xf1, 0x13, 0xd0, 0x58, 0x0b, 0xdf, 0xcb, 0x0f, 0xfd, 0xcb, 0xaf, 0x2a, 0xa6, 0x41, 0x28, 0xed, 0x78, 0x20, 0xd1, 0x0e, 0xca, 0xfa, 0x2c, 0x71, 0xaa, 0xf0, 0xce, 0xca, 0x12, 0x0e, 0x6b, 0x50, 0x82, 0xf0, 0xa9, 0x97, 0xc1, 0x08, 0xbc, 0xc9, 0xe5, 0xd4, 0x29, 0x76, 0xe6, 0x1b, 0x95, 0x81, 0x6f, 0x76, 0xe8, 0x8c, 0x3f, 0x01, 0xb3, 0x2f, 0xc6, 0x3c, 0x75, 0x78, 0xc5, 0xdf, 0xd1, 0xa9, 0xa8, 0x9d, 0x05, 0x22, 0x92, 0x90, 0xd9, 0xd8, 0x0f, 0xd4, 0xce, 0xeb, 0x4c, 0x9c, 0x83, 0x2e, 0x5e, 0xef, 0x60, 0x5e, 0xfd, 0xde, 0x27, 0x2f, 0x50, 0x95, 0x2f, 0x5d, 0xa9, 0x81, 0x63, 0x56, 0x1f, 0x36, 0x67, 0xb7, 0xbf, 0x74, 0x0d, 0x2c, 0xdc, 0x86, 0xe5, 0x01, 0xdf, 0xbf, 0x2a, 0x0e, 0xcd, 0x06, 0xf5, 0x88, 0xcd, 0x4c, 0x4b, 0xaa, 0x59, 0x8e, 0x58, 0x4f, 0x4f, 0x72, 0x50, 0x7d, 0x3b, 0x07, 0x0d, 0xbf, 0x18, 0xe0, 0x03, 0xcb, 0x59, 0x25, 0x41, 0x7d, 0x7e, 0xc8, 0x30, 0xfa, 0xd9, 0xc1, 0x2a, 0xea, 0x86, 0x3b, 0xa2, 0x1e, 0x95, 0xad, 0xe3, 0xbe, 0x29, 0xe3, 0x43, 0x8e, 0x87, 0x0e, 0xbb, 0xb8, 0xce, 0xc6, 0x60, 0x23, 0xd1, 0x51, 0x33, 0xf4, 0xbc, 0xa6, 0xe5, 0xed, 0x7c, 0x61, 0x99, 0x2a, 0x55, 0x66, 0xed, 0xa5, 0x5c, 0x99, 0x3a, 0x46, 0xa2, 0xdc, 0xaf, 0xc3, 0x0d, 0x6b, 0x6d, 0xaa, 0x53, 0xca, 0x08, 0x18, 0x70, 0x2d, 0xc9, 0xf4, 0x90, 0xdb, 0x78, 0x40, 0x32, 0x97, 0xc6, 0x8d, 0x35, 0x26, 0x09, 0x1c, 0x1f, 0x53, 0xf8, 0xe4, 0x1c, 0xe7, 0xfd, 0x6d, 0x18, 0x30, 0x4f, 0x98, 0x7e, 0x86, 0x28, 0x6d, 0x9d, 0xae, 0xa0, 0x34, 0x04, 0x19, 0x4e, 0xa3, 0x9e, 0x54, 0x45, 0xeb, 0x48, 0x2b, 0xf0, 0xf8, 0x97, 0x12, 0xa3, 0xaa, 0xb4, 0xe8, 0xbf, 0x41, 0x72, 0x74, 0xbc, 0x88, 0xbf, 0x3c, 0x46, 0x1c, 0x6a, 0x37, 0x69, 0xa1, 0x78, 0x67, 0xc8, 0x34, 0x24, 0x71, 0x98, 0x1c, 0x10, 0xdb, 0x8a, 0x2e, 0x77, 0xea, 0x50, 0xa2, 0x27, 0x11, 0x34, 0x71, 0x5f, 0xc1, 0x66, 0xa3, 0xe5, 0x65, 0xda, 0x60, 0xb3, 0xf3, 0x22, 0x5c, 0x7c, 0xef, 0x5f, 0x6d, 0xd8, 0x1c, 0xe0, 0x88, 0x71, 0x8f, 0xb3, 0x3e, 0x1a, 0xd6, 0x07, 0x26, 0x22, 0x90, 0x56, 0x9a, 0x48, 0x79, 0xc5, 0x61, 0xe6, 0x05, 0xee, 0xb2, 0x7d, 0xdc, 0x7c, 0xc2, 0x9c, 0x7f, 0x26, 0x7e, 0xbf, 0xcf, 0xb5, 0x4f, 0x47, 0x05, 0x00, 0x07, 0xce, 0x48, 0xec, 0x6d, 0x47, 0x15, 0x1d, 0x1c, 0xc2, 0xbe, 0x38, 0x21, 0x9b, 0xd1, 0x9c, 0xb4, 0xd0, 0xe1, 0x1b, 0x12, 0x0b, 0x7e, 0x2e, 0x2b, 0xd7, 0x40, 0x33, 0xd4, 0x47, 0xff, 0xf2, 0xeb, 0x59, 0x36, 0xbb, 0x03, 0xb2, 0x69, 0x45, 0xb4, 0x7c, 0xa5, 0x42, 0xc6, 0x7d, 0xcf, 0x38, 0x7e, 0xf3, 0x45, 0x6c, 0xe7, 0xb4, 0xb5, 0xaf, 0x83, 0x1f, 0xa9, 0x39, 0xef, 0x76, 0x10, 0x7e, 0xe0, 0x15];
    //let plaintext = [0x48, 0x54, 0x54, 0x50, 0x2f, 0x31, 0x2e, 0x31, 0x20, 0x32, 0x30, 0x30, 0x20, 0x4f, 0x4b, 0x0d, 0x0a, 0x53, 0x65, 0x72, 0x76, 0x65, 0x72, 0x3a, 0x20, 0x73, 0x63, 0x61, 0x66, 0x66, 0x6f, 0x6c, 0x64, 0x69, 0x6e, 0x67, 0x20, 0x6f, 0x6e, 0x20, 0x48, 0x54, 0x54, 0x50, 0x53, 0x65, 0x72, 0x76, 0x65, 0x72, 0x32, 0x0d, 0x0a, 0x58, 0x2d, 0x58, 0x53, 0x53, 0x2d, 0x50, 0x72, 0x6f, 0x74, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x3a, 0x20, 0x30, 0x0d, 0x0a, 0x58, 0x2d, 0x46, 0x72, 0x61, 0x6d, 0x65, 0x2d, 0x4f, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x3a, 0x20, 0x53, 0x41, 0x4d, 0x45, 0x4f, 0x52, 0x49, 0x47, 0x49, 0x4e, 0x0d, 0x0a, 0x58, 0x2d, 0x43, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2d, 0x54, 0x79, 0x70, 0x65, 0x2d, 0x4f, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x3a, 0x20, 0x6e, 0x6f, 0x73, 0x6e, 0x69, 0x66, 0x66, 0x0d, 0x0a, 0x44, 0x61, 0x74, 0x65, 0x3a, 0x20, 0x46, 0x72, 0x69, 0x2c, 0x20, 0x32, 0x30, 0x20, 0x4a, 0x75, 0x6e, 0x20, 0x32, 0x30, 0x32, 0x35, 0x20, 0x31, 0x36, 0x3a, 0x33, 0x39, 0x3a, 0x32, 0x35, 0x20, 0x47, 0x4d, 0x54, 0x0d, 0x0a, 0x45, 0x78, 0x70, 0x69, 0x72, 0x65, 0x73, 0x3a, 0x20, 0x46, 0x72, 0x69, 0x2c, 0x20, 0x32, 0x30, 0x20, 0x4a, 0x75, 0x6e, 0x20, 0x32, 0x30, 0x32, 0x35, 0x20, 0x32, 0x31, 0x3a, 0x35, 0x33, 0x3a, 0x33, 0x32, 0x20, 0x47, 0x4d, 0x54, 0x0d, 0x0a, 0x43, 0x61, 0x63, 0x68, 0x65, 0x2d, 0x43, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x3a, 0x20, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x2c, 0x20, 0x6d, 0x61, 0x78, 0x2d, 0x61, 0x67, 0x65, 0x3d, 0x31, 0x38, 0x38, 0x34, 0x37, 0x2c, 0x20, 0x6d, 0x75, 0x73, 0x74, 0x2d, 0x72, 0x65, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x61, 0x74, 0x65, 0x2c, 0x20, 0x6e, 0x6f, 0x2d, 0x74, 0x72, 0x61, 0x6e, 0x73, 0x66, 0x6f, 0x72, 0x6d, 0x0d, 0x0a, 0x43, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2d, 0x54, 0x79, 0x70, 0x65, 0x3a, 0x20, 0x61, 0x70, 0x70, 0x6c, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2f, 0x6a, 0x73, 0x6f, 0x6e, 0x3b, 0x20, 0x63, 0x68, 0x61, 0x72, 0x73, 0x65, 0x74, 0x3d, 0x55, 0x54, 0x46, 0x2d, 0x38, 0x0d, 0x0a, 0x41, 0x67, 0x65, 0x3a, 0x20, 0x32, 0x39, 0x0d, 0x0a, 0x41, 0x6c, 0x74, 0x2d, 0x53, 0x76, 0x63, 0x3a, 0x20, 0x68, 0x33, 0x3d, 0x22, 0x3a, 0x34, 0x34, 0x33, 0x22, 0x3b, 0x20, 0x6d, 0x61, 0x3d, 0x32, 0x35, 0x39, 0x32, 0x30, 0x30, 0x30, 0x2c, 0x68, 0x33, 0x2d, 0x32, 0x39, 0x3d, 0x22, 0x3a, 0x34, 0x34, 0x33, 0x22, 0x3b, 0x20, 0x6d, 0x61, 0x3d, 0x32, 0x35, 0x39, 0x32, 0x30, 0x30, 0x30, 0x0d, 0x0a, 0x41, 0x63, 0x63, 0x65, 0x70, 0x74, 0x2d, 0x52, 0x61, 0x6e, 0x67, 0x65, 0x73, 0x3a, 0x20, 0x6e, 0x6f, 0x6e, 0x65, 0x0d, 0x0a, 0x56, 0x61, 0x72, 0x79, 0x3a, 0x20, 0x4f, 0x72, 0x69, 0x67, 0x69, 0x6e, 0x2c, 0x58, 0x2d, 0x4f, 0x72, 0x69, 0x67, 0x69, 0x6e, 0x2c, 0x52, 0x65, 0x66, 0x65, 0x72, 0x65, 0x72, 0x2c, 0x41, 0x63, 0x63, 0x65, 0x70, 0x74, 0x2d, 0x45, 0x6e, 0x63, 0x6f, 0x64, 0x69, 0x6e, 0x67, 0x0d, 0x0a, 0x43, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x3a, 0x20, 0x63, 0x6c, 0x6f, 0x73, 0x65, 0x0d, 0x0a, 0x54, 0x72, 0x61, 0x6e, 0x73, 0x66, 0x65, 0x72, 0x2d, 0x45, 0x6e, 0x63, 0x6f, 0x64, 0x69, 0x6e, 0x67, 0x3a, 0x20, 0x63, 0x68, 0x75, 0x6e, 0x6b, 0x65, 0x64, 0x0d, 0x0a, 0x0d, 0x0a, 0x34, 0x30, 0x39, 0x0d, 0x0a, 0x7b, 0x0a, 0x20, 0x20, 0x22, 0x6b, 0x65, 0x79, 0x73, 0x22, 0x3a, 0x20, 0x5b, 0x0a, 0x20, 0x20, 0x20, 0x20, 0x7b, 0x0a, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x22, 0x61, 0x6c, 0x67, 0x22, 0x3a, 0x20, 0x22, 0x52, 0x53, 0x32, 0x35, 0x36, 0x22, 0x2c, 0x0a, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x22, 0x6e, 0x22, 0x3a, 0x20, 0x22, 0x73, 0x53, 0x53, 0x44, 0x59, 0x73, 0x35, 0x32, 0x53, 0x55, 0x6e, 0x59, 0x65, 0x68, 0x78, 0x4f, 0x56, 0x2d, 0x47, 0x5f, 0x65, 0x51, 0x34, 0x37, 0x53, 0x6d, 0x4d, 0x38, 0x6d, 0x39, 0x75, 0x62, 0x54, 0x55, 0x55, 0x30, 0x4b, 0x32, 0x34, 0x4c, 0x70, 0x4e, 0x48, 0x6b, 0x37, 0x6a, 0x34, 0x49, 0x43, 0x4d, 0x2d, 0x50, 0x72, 0x65, 0x42, 0x69, 0x5f, 0x6e, 0x70, 0x42, 0x66, 0x78, 0x79, 0x37, 0x6b, 0x41, 0x6f, 0x42, 0x72, 0x35, 0x4b, 0x53, 0x5f, 0x44, 0x70, 0x32, 0x46, 0x41, 0x52, 0x33, 0x32, 0x6a, 0x69, 0x37, 0x65, 0x79, 0x34, 0x32, 0x4a, 0x74, 0x7a, 0x45, 0x2d, 0x78, 0x72, 0x6b, 0x7a, 0x41, 0x49, 0x31, 0x46, 0x6d, 0x62, 0x4c, 0x35, 0x56, 0x6d, 0x78, 0x52, 0x32, 0x44, 0x33, 0x4a, 0x74, 0x4b, 0x34, 0x53, 0x39, 0x4b, 0x79, 0x74, 0x64, 0x35, 0x64, 0x38, 0x78, 0x63, 0x4e, 0x64, 0x73, 0x42, 0x64, 0x41, 0x48, 0x45, 0x6d, 0x6f, 0x51, 0x79, 0x6a, 0x6a, 0x41, 0x61, 0x66, 0x4c, 0x42, 0x6e, 0x78, 0x2d, 0x48, 0x77, 0x47, 0x4a, 0x65, 0x30, 0x43, 0x37, 0x47, 0x33, 0x56, 0x4a, 0x5a, 0x58, 0x4f, 0x75, 0x34, 0x2d, 0x6b, 0x4b, 0x56, 0x76, 0x34, 0x72, 0x71, 0x77, 0x6c, 0x6e, 0x2d, 0x50, 0x75, 0x4d, 0x6c, 0x77, 0x46, 0x7a, 0x39, 0x44, 0x4e, 0x72, 0x34, 0x75, 0x42, 0x55, 0x67, 0x76, 0x74, 0x71, 0x6d, 0x42, 0x50, 0x53, 0x58, 0x64, 0x41, 0x6a, 0x52, 0x73, 0x6b, 0x62, 0x4d, 0x4a, 0x43, 0x6f, 0x34, 0x65, 0x57, 0x72, 0x52, 0x58, 0x63, 0x7a, 0x51, 0x65, 0x72, 0x64, 0x35, 0x6e, 0x6f, 0x51, 0x41, 0x51, 0x6f, 0x5a, 0x6d, 0x52, 0x4e, 0x46, 0x53, 0x31, 0x38, 0x46, 0x63, 0x63, 0x44, 0x63, 0x74, 0x34, 0x65, 0x66, 0x75, 0x54, 0x34, 0x39, 0x70, 0x48, 0x37, 0x42, 0x41, 0x68, 0x79, 0x35, 0x59, 0x48, 0x66, 0x41, 0x46, 0x76, 0x38, 0x76, 0x4d, 0x67, 0x43, 0x70, 0x52, 0x68, 0x71, 0x64, 0x32, 0x56, 0x41, 0x44, 0x59, 0x4a, 0x66, 0x42, 0x56, 0x6c, 0x4a, 0x38, 0x77, 0x4b, 0x4d, 0x43, 0x43, 0x2d, 0x38, 0x79, 0x7a, 0x63, 0x6b, 0x4c, 0x6a, 0x39, 0x56, 0x32, 0x55, 0x51, 0x5a, 0x53, 0x4f, 0x6d, 0x4a, 0x33, 0x49, 0x6f, 0x42, 0x6f, 0x76, 0x6e, 0x46, 0x30, 0x32, 0x45, 0x4e, 0x30, 0x75, 0x4c, 0x30, 0x62, 0x59, 0x4d, 0x75, 0x6e, 0x56, 0x76, 0x6d, 0x30, 0x59, 0x57, 0x50, 0x72, 0x51, 0x22, 0x2c, 0x0a, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x22, 0x6b, 0x69, 0x64, 0x22, 0x3a, 0x20, 0x22, 0x30, 0x64, 0x38, 0x61, 0x36, 0x37, 0x33, 0x39, 0x39, 0x65, 0x37, 0x38, 0x38, 0x32, 0x61, 0x63, 0x61, 0x65, 0x37, 0x64, 0x37, 0x66, 0x36, 0x38, 0x62, 0x32, 0x32, 0x38, 0x30, 0x32, 0x35, 0x36, 0x61, 0x37, 0x39, 0x36, 0x61, 0x35, 0x38, 0x32, 0x22, 0x2c, 0x0a, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x22, 0x6b, 0x74, 0x79, 0x22, 0x3a, 0x20, 0x22, 0x52, 0x53, 0x41, 0x22, 0x2c, 0x0a, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x22, 0x65, 0x22, 0x3a, 0x20, 0x22, 0x41, 0x51, 0x41, 0x42, 0x22, 0x2c, 0x0a, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x22, 0x75, 0x73, 0x65, 0x22, 0x3a, 0x20, 0x22, 0x73, 0x69, 0x67, 0x22, 0x0a, 0x20, 0x20, 0x20, 0x20, 0x7d, 0x2c, 0x0a, 0x20, 0x20, 0x20, 0x20, 0x7b, 0x0a, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x22, 0x61, 0x6c, 0x67, 0x22, 0x3a, 0x20, 0x22, 0x52, 0x53, 0x32, 0x35, 0x36, 0x22, 0x2c, 0x0a, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x22, 0x6e, 0x22, 0x3a, 0x20, 0x22, 0x7a, 0x5f, 0x4d, 0x35, 0x68, 0x33, 0x58, 0x43, 0x7a, 0x65, 0x67, 0x66, 0x4f, 0x47, 0x37, 0x6a, 0x46, 0x59, 0x47, 0x57, 0x55, 0x49, 0x75, 0x77, 0x6a, 0x61, 0x5a, 0x35, 0x2d, 0x52, 0x45, 0x5f, 0x63, 0x46, 0x68, 0x6a, 0x7a, 0x64, 0x75, 0x61, 0x68, 0x4e, 0x4a, 0x70, 0x76, 0x5f, 0x73, 0x45, 0x42, 0x44, 0x5f, 0x4b, 0x36, 0x5a, 0x75, 0x61, 0x72, 0x56, 0x54, 0x41, 0x66, 0x59, 0x50, 0x5f, 0x35, 0x66, 0x66, 0x36, 0x6e, 0x55, 0x42, 0x6b, 0x46, 0x79, 0x75, 0x31, 0x44, 0x5a, 0x37, 0x70, 0x5a, 0x69, 0x4e, 0x4a, 0x5f, 0x72, 0x74, 0x56, 0x66, 0x65, 0x66, 0x64, 0x5f, 0x6d, 0x43, 0x55, 0x5a, 0x58, 0x36, 0x69, 0x6f, 0x4c, 0x72, 0x6a, 0x30, 0x49, 0x4a, 0x4e, 0x67, 0x63, 0x57, 0x39, 0x39, 0x7a, 0x67, 0x36, 0x4b, 0x5a, 0x32, 0x39, 0x49, 0x63, 0x65, 0x6f, 0x4f, 0x39, 0x6c, 0x36, 0x30, 0x31, 0x62, 0x79, 0x37, 0x61, 0x6b, 0x7a, 0x4a, 0x6a, 0x30, 0x4e, 0x49, 0x67, 0x32, 0x49, 0x39, 0x4c, 0x33, 0x30, 0x50, 0x77, 0x34, 0x50, 0x63, 0x42, 0x51, 0x75, 0x53, 0x6a, 0x4b, 0x79, 0x69, 0x75, 0x4a, 0x51, 0x54, 0x33, 0x55, 0x4a, 0x52, 0x33, 0x5a, 0x65, 0x50, 0x45, 0x4e, 0x68, 0x30, 0x35, 0x48, 0x55, 0x39, 0x43, 0x5a, 0x42, 0x59, 0x32, 0x7a, 0x4d, 0x4f, 0x76, 0x47, 0x38, 0x77, 0x42, 0x63, 0x38, 0x34, 0x4a, 0x34, 0x78, 0x4b, 0x58, 0x46, 0x38, 0x6e, 0x4a, 0x4e, 0x73, 0x55, 0x2d, 0x6c, 0x65, 0x47, 0x59, 0x7a, 0x78, 0x52, 0x36, 0x46, 0x61, 0x75, 0x61, 0x79, 0x79, 0x42, 0x35, 0x66, 0x36, 0x49, 0x5f, 0x6e, 0x76, 0x5a, 0x44, 0x45, 0x70, 0x39, 0x51, 0x7a, 0x47, 0x45, 0x56, 0x46, 0x4d, 0x58, 0x30, 0x4a, 0x37, 0x56, 0x4e, 0x63, 0x5a, 0x79, 0x59, 0x55, 0x45, 0x68, 0x32, 0x5a, 0x37, 0x77, 0x59, 0x57, 0x58, 0x39, 0x72, 0x79, 0x73, 0x7a, 0x44, 0x34, 0x30, 0x7a, 0x58, 0x55, 0x46, 0x62, 0x74, 0x52, 0x54, 0x39, 0x70, 0x4e, 0x44, 0x38, 0x68, 0x61, 0x55, 0x63, 0x48, 0x5f, 0x48, 0x64, 0x73, 0x79, 0x32, 0x74, 0x65, 0x59, 0x6c, 0x48, 0x71, 0x74, 0x78, 0x34, 0x49, 0x50, 0x79, 0x4c, 0x39, 0x50, 0x44, 0x17];

    let mut len_of_first_packet = (http_response[3] as usize)*256 + (http_response[4] as usize) + 5;
    println!("len_of_first_packet is : {:?}", &len_of_first_packet);

    let mut iv = server_application_iv.clone();
    //let mut records_received: u8 = 1;
    iv[11] ^= records_received;

    let mut plaintext = decrypt(&server_application_key, &iv.try_into().unwrap(), &http_response[..len_of_first_packet]);
    //println!("decrypted app plaintext is : {:?}", &plaintext);
    println!("{}", String::from_utf8_lossy(&plaintext));
    plaintext = format::trunc_end_23(&plaintext);//plaintext.pop();

    while records_received<records_received_declared-1 {
        // Увеличиваем количество полученных записей
        records_received += 1;
        let start_index = len_of_first_packet;
        let len_of_packet = (http_response[start_index+3] as usize)*256 + (http_response[start_index+4] as usize) + 5;
        //println!("len_of_packet is : {:?}", &len_of_packet);

        let ciphertext2 = &http_response[len_of_first_packet..len_of_first_packet + len_of_packet];
        //println!("ciphertext2 is : {:?}", &ciphertext2);
        let mut iv2 = server_application_iv.clone();
        iv2[11] ^= records_received;
        let mut plaintext2 = decrypt(&server_application_key, &iv2.try_into().unwrap(), &ciphertext2);
        println!("decrypted app plaintext2 is : {:?}", &plaintext2);
        //plaintext2.pop();
        plaintext2 = format::trunc_end_23(&plaintext2);

        plaintext.append(&mut plaintext2);
        len_of_first_packet = len_of_first_packet + len_of_packet;

        //println!("{}", String::from_utf8_lossy(&plaintext));
    }
    //println!("{}", String::from_utf8_lossy(&plaintext));




    let plaintext_as_string = String::from_utf8_lossy(&plaintext).to_string();

    let expires_timestamp = format::extract_expires(&plaintext_as_string);

    let strings_n = format::extract_all_items("n",&plaintext_as_string); // = format::extract_all_n(&plaintext_as_string);
    let strings_kid = format::extract_all_items("kid",&plaintext_as_string);

    //let mut hashes_n: Vec<u8> = Vec::new();
    let mut counter = 0;

    for substring in strings_kid {
        println!("Found kid: {}", substring);

        //let mut current = substring.as_bytes().to_vec();
        let mut current_decoded_kid = Vec::from_hex(substring).unwrap();
        println!("current_decoded_kid is : {:?}", &current_decoded_kid);

        if current_decoded_kid.eq(&kid.to_vec()){
            println!("current n is : {:?}", &strings_n[counter]);
            let mut current_decoded_n = decode(&strings_n[counter]).unwrap();
            println!("current_decoded_n is : {:?}", &current_decoded_n);
            let mut result = vec![1u8];

            append_uint64(&mut result, expires_timestamp as u64);

            result.append(&mut current_decoded_n.to_vec());

            return result;

        }

        //let hash_of_current_n = hkdf_sha256::sum256( &current_decoded_n);
        //hashes_n.append(&mut hash_of_current_n.to_vec());
        counter += 1;
    }

    //let mut result = vec![1u8];
    //result.push(strings_n.len() as u8);
    //result.append(&mut hashes_n);

    //let expires_timestamp = format::extract_expires(&plaintext_as_string);
    //result.append(&mut expires_timestamp.to_be_bytes().to_vec());


    return vec![0u8, 3u8, 43u8]; // "kid not found "
}



/*
#[test]
fn cc_decrypt_test_with_data_from_go(){
    let record = [23, 3, 3, 2, 23, 177, 157, 133, 253, 223, 147, 18, 161, 225, 173, 50, 130, 43, 133, 226, 113, 87, 169, 120, 136, 86, 36,
        194, 193, 185, 211, 107, 149, 21, 172, 77, 76, 115, 30, 64, 125, 219, 68, 96, 237, 233, 219, 108, 247, 211, 214, 99, 201, 10, 116, 151, 147,
        57, 229, 193, 165, 234, 129, 127, 81, 232, 13, 252, 14, 119, 151, 143, 5, 131, 143, 50, 252, 68, 165, 222, 146, 213, 104, 16, 165, 60, 255,
        24, 101, 168, 93, 134, 236, 92, 94, 254, 202, 116, 11, 205, 137, 20, 110, 173, 4, 12, 185, 48, 32, 243, 58, 189, 212, 129, 48, 250, 75, 0,
        94, 117, 182, 131, 53, 254, 209, 60, 205, 0, 0, 55, 122, 82, 74, 31, 140, 119, 86, 112, 211, 147, 114, 215, 2, 131, 236, 198, 37, 223, 217,
        185, 195, 195, 228, 177, 90, 104, 117, 204, 10, 81, 252, 17, 171, 60, 92, 46, 69, 8, 230, 65, 54, 130, 184, 89, 36, 43, 7, 157, 72, 35, 134,
        25, 207, 105, 164, 150, 129, 47, 154, 196, 213, 32, 210, 59, 11, 103, 19, 23, 0, 226, 34, 179, 188, 2, 70, 199, 80, 190, 108, 47, 27, 68, 179,
        127, 148, 17, 233, 231, 194, 142, 204, 254, 60, 63, 172, 167, 204, 82, 177, 110, 123, 137, 128, 163, 71, 163, 171, 129, 241, 131, 69, 123, 207, 102, 148, 14, 215, 189, 212, 156, 233, 45, 54, 174, 57, 110, 152, 63, 166, 159, 49, 212, 51, 157, 40, 161, 9, 40, 121, 153, 42, 125, 199, 1, 170, 116, 199, 208, 112, 162, 6, 200, 108, 109, 91, 16, 43, 32, 17, 161, 159, 115, 122, 132, 180, 97, 143, 127, 198, 176, 15, 188, 188, 239, 74, 249, 195, 235, 2, 233, 88, 100, 201, 172, 253, 167, 198, 20, 113, 218, 132, 29, 37, 156, 117, 250, 105, 122, 61, 167, 52, 122, 158, 68, 202, 245, 89, 78, 238, 37, 176, 79, 85, 23, 236, 134, 99, 125, 45, 93, 214, 34, 62, 38, 136, 14, 30, 5, 142, 238, 255, 169, 0, 214, 219, 8, 121, 37, 191, 226, 220, 103, 198, 237, 98, 125, 128, 52, 93, 93, 165, 197, 27, 23, 87, 45, 176, 34, 65, 163, 74, 251, 104, 85, 200, 201, 178, 56, 97, 112, 155, 178, 57, 11, 18, 106, 38, 24, 163, 39, 43, 73, 107, 13, 100, 73, 33, 56, 189, 14, 103, 238, 233, 29, 184, 221, 46, 253, 104, 222, 252, 11, 77, 204, 212, 146, 16, 209, 54, 178, 96, 108, 62, 216, 197, 224, 77, 53, 20, 14, 98, 86, 32, 132, 205, 244, 139, 106, 170, 52, 219, 70, 180, 57, 182, 119, 34, 215, 14, 198, 166, 14, 157, 158, 215, 88, 224, 148, 170, 184, 57, 119, 111, 175, 236, 70, 122, 180, 103, 32, 216, 168, 33, 190, 90, 23, 194, 52, 187, 91, 148, 218, 179, 116, 105, 18, 91, 19, 7, 196, 160, 241, 24, 79, 148, 68, 227, 107, 83, 228, 46, 179, 9, 97, 169, 4, 19, 80, 33, 246, 162, 121, 207, 217, 189, 199, 160, 103, 21, 89];

    let iv = [99, 126, 235, 174, 99, 203, 101, 174, 149, 148, 71, 186];
    let keys_server_application_key = [222, 187, 47, 7, 103, 63, 28, 206, 140, 228, 229, 211, 177, 58, 151, 120];

    let etalon_plaintext = [4, 0, 0, 255, 0, 2, 163, 0, 152, 53, 48, 122, 1, 0, 0, 229, 2, 20, 217, 168, 201, 124, 209, 130, 183, 238, 248, 199, 28,
        85, 254, 123, 28, 223, 67, 228, 121, 118, 8, 206, 136, 172, 101, 119, 25, 106, 218, 151, 101, 139, 70, 208, 169, 45, 53, 100, 45, 64, 46, 60,
        186, 12, 132, 125, 30, 229, 58, 233, 202, 205, 35, 189, 105, 7, 72, 25, 162, 0, 98, 157, 148, 127, 157, 13, 155, 15, 0, 108, 93, 19, 70, 162,
        39, 209, 223, 152, 103, 219, 61, 234, 130, 22, 15, 112, 223, 124, 148, 163, 63, 255, 210, 199, 53, 178, 0, 38, 118, 62, 245, 148, 157, 181, 74,
        223, 214, 40, 33, 72, 143, 27, 144, 157, 29, 98, 179, 113, 154, 125, 225, 171, 186, 217, 81, 254, 178, 37, 252, 50, 8, 177, 144, 153, 97, 77,
        159, 233, 98, 12, 86, 20, 81, 185, 104, 68, 44, 181, 129, 25, 85, 45, 195, 88, 55, 103, 186, 155, 9, 183, 85, 76, 156, 109, 29, 206, 165, 142,
        166, 253, 199, 225, 224, 114, 99, 62, 239, 224, 95, 7, 31, 130, 83, 197, 4, 224, 180, 188, 210, 121, 130, 213, 201, 245, 119, 9, 69, 151, 74,
        212, 19, 178, 163, 179, 89, 226, 253, 119, 179, 12, 68, 92, 241, 45, 121, 95, 72, 69, 77, 248, 29, 97, 217, 124, 124, 5, 68, 0, 12, 0, 42, 0,
        4, 0, 0, 56, 0, 138, 138, 0, 0, 4, 0, 0, 255, 0, 2, 163, 0, 38, 9, 175, 91, 1, 1, 0, 229, 2, 20, 217, 168, 201, 124, 209, 130, 183, 238, 248,
        199, 28, 85, 254, 123, 40, 188, 64, 132, 133, 138, 84, 210, 53, 166, 9, 138, 53, 225, 158, 116, 9, 229, 213, 56, 193, 168, 212, 231, 181, 192,
        191, 6, 90, 9, 206, 43, 196, 176, 250, 212, 159, 136, 132, 172, 96, 139, 117, 197, 22, 214, 59, 195, 212, 74, 128, 233, 170, 6, 216, 65, 73,
        12, 222, 219, 132, 6, 36, 252, 140, 220, 105, 194, 211, 199, 47, 43, 216, 26, 101, 71, 238, 106, 122, 165, 56, 19, 20, 210, 68, 9, 220, 225,
        151, 200, 2, 145, 28, 9, 179, 205, 144, 19, 1, 50, 229, 219, 66, 12, 165, 143, 27, 134, 157, 243, 221, 236, 129, 154, 69, 180, 129, 78, 87,
        164, 109, 135, 241, 80, 158, 240, 87, 116, 61, 166, 100, 226, 234, 237, 69, 193, 235, 195, 238, 141, 204, 4, 235, 63, 21, 204, 115, 126, 53, 13,
        128, 245, 23, 157, 101, 226, 185, 225, 88, 90, 75, 251, 189, 64, 255, 122, 118, 66, 62, 43, 243, 205, 91, 27, 2, 253, 41, 67, 20, 104, 194, 211, 4, 237, 52, 195, 62, 157, 158, 50, 101, 119, 247, 194, 122, 251, 232, 34, 154, 242, 211, 197, 72, 69, 77, 255, 55, 218, 203, 0, 137, 180, 224, 0, 12, 0, 42, 0, 4, 0, 0, 56, 0, 138, 138, 0, 0, 22];

    let plaintext = decrypt(&keys_server_application_key, &iv, &record);
    println!("plaintext is : {:?}", plaintext);

    assert_eq!(plaintext, etalon_plaintext);
}

#[test]
fn cc_encrypt_test_with_data_from_go(){
    let additional = [23, 3, 3, 0, 95];
    let data = [71, 69, 84, 32, 47, 111, 97, 117, 116, 104, 50, 47, 118, 51, 47, 99, 101, 114, 116, 115, 32, 72, 84, 84, 80, 47, 49, 46, 49, 13, 10, 72, 111, 115, 116, 58, 32, 119, 119, 119, 46, 103, 111, 111, 103, 108, 101, 97, 112, 105, 115, 46, 99, 111, 109, 13, 10, 67, 111, 110, 110, 101, 99, 116, 105, 111, 110, 58, 32, 99, 108, 111, 115, 101, 13, 10, 13, 10, 23];
    let keys_client_application_iv = [208, 90, 11, 166, 158, 89, 74, 229, 93, 100, 190, 96];
    let keys_client_application_key =[202, 43, 126, 184, 251, 151, 149, 225, 187, 12, 226, 41, 245, 118, 60, 75];
    let etalon_ciphertext = [23, 3, 3, 0, 95, 192, 206, 156, 237, 152, 153, 248, 195, 170, 179, 216, 15, 49, 39, 0, 169, 60, 76, 192, 117, 116, 172, 193, 165, 123, 147, 85, 229, 71, 50, 78, 252, 97, 160, 34, 92, 149, 251, 139, 117, 207, 175, 231, 163, 202, 186, 62, 178, 12, 54, 168, 84, 50, 56, 232, 44, 185, 241, 188, 244, 223, 211, 179, 47, 56, 202, 172, 237, 174, 91, 66, 83, 221, 176, 11, 4, 194, 127, 29, 63, 218, 104, 56, 241, 53, 109, 102, 59, 180, 246, 41, 251, 42, 202, 48];

    let ciphertext = encrypt(&keys_client_application_key, &keys_client_application_iv, &data, &additional);
    println!("ciphertext is : {:?}", ciphertext);

    assert_eq!(ciphertext[..], etalon_ciphertext);
}

#[test]
fn test_check_serialized(){
    let serialized_tls = [231, 226, 189, 128, 175, 192, 46, 233, 160, 243, 227, 168, 186, 174, 207, 111, 124, 21, 6, 220, 18, 155, 18, 17, 39, 165, 203, 108, 109, 3, 40, 186,
        1, 3, 22, 3, 1, 0, 161, 1, 0, 0, 157, 3, 3, 89, 5, 189, 214, 6, 206, 207, 223, 70, 97, 80, 150, 184, 229, 217, 99, 94, 163, 211, 149, 114, 208, 147, 193, 67, 39,
        104, 231, 181, 211, 97, 30, 0, 0, 2, 19, 1, 1, 0, 0, 114, 0, 0, 0, 23, 0, 21, 0, 0, 18, 119, 119, 119, 46, 103, 111, 111, 103, 108, 101, 97, 112, 105, 115, 46, 99,
        111, 109, 0, 10, 0, 4, 0, 2, 0, 29, 0, 13, 0, 20, 0, 18, 4, 3, 8, 4, 4, 1, 5, 3, 8, 5, 5, 1, 8, 6, 6, 1, 2, 1, 0, 51, 0, 38, 0, 36, 0, 29, 0, 32, 192, 66, 56, 95,
        6, 86, 129, 217, 28, 232, 5, 177, 109, 189, 139, 154, 6, 3, 215, 62, 202, 195, 214, 238, 231, 82, 157, 198, 107, 200, 81, 16, 0, 45, 0, 2, 1, 1, 0, 43, 0, 3, 2, 3,
        4, 22, 3, 3, 0, 90, 2, 0, 0, 86, 3, 3, 82, 184, 102, 244, 4, 252, 76, 20, 193, 246, 137, 35, 192, 223, 27, 135, 201, 193, 203, 77, 206, 115, 60, 104, 71, 140, 245,
        68, 133, 225, 90, 93, 0, 19, 1, 0, 0, 46, 0, 51, 0, 36, 0, 29, 0, 32, 0, 116, 86, 213, 40, 17, 162, 247, 99, 76, 7, 89, 113, 113, 225, 218, 215, 41, 1, 253, 139, 192,
        118, 225, 68, 124, 251, 53, 8, 27, 109, 64, 0, 43, 0, 2, 3, 4, 23, 3, 3, 16, 249, 219, 135, 222, 204, 252, 242, 204, 235, 193, 254, 62, 149, 60, 118, 129, 78, 159, 144,
        224, 126, 32, 125, 227, 234, 12, 86, 177, 43, 141, 98, 124, 115, 16, 251, 246, 66, 240, 85, 208, 182, 179, 238, 130, 70, 139, 236, 5, 197, 167, 205, 0, 17, 23, 139, 80,
        172, 126, 174, 25, 85, 100, 143, 65, 187, 97, 210, 89, 1, 41, 82, 204, 178, 127, 56, 114, 140, 173, 19, 24, 1, 154, 30, 194, 14, 15, 221, 106, 243, 240, 30, 8, 236, 251,
        92, 72, 81, 140, 186, 25, 217, 100, 24, 195, 68, 105, 13, 247, 128, 135, 249, 124, 151, 193, 229, 78, 77, 13, 101, 65, 182, 9, 38, 187, 218, 67, 251, 4, 123, 173, 121,
        100, 255, 63, 152, 156, 237, 110, 163, 156, 13, 84, 9, 54, 226, 137, 48, 178, 80, 66, 32, 58, 230, 219, 31, 193, 77, 203, 164, 77, 130, 207, 26, 58, 201, 191, 107, 95,
        185, 188, 66, 146, 212, 150, 113, 231, 188, 7, 11, 172, 80, 28, 137, 171, 66, 124, 168, 226, 212, 89, 151, 129, 86, 143, 20, 47, 149, 165, 235, 106, 236, 225, 175, 117,
        47, 40, 126, 51, 55, 9, 202, 110, 245, 189, 160, 8, 29, 122, 79, 159, 7, 237, 137, 73, 246, 171, 35, 56, 106, 16, 133, 254, 123, 136, 139, 199, 96, 61, 43, 183, 9, 106,
        205, 61, 169, 97, 211, 210, 134, 150, 155, 40, 227, 0, 94, 228, 105, 232, 60, 35, 22, 235, 124, 249, 146, 111, 73, 174, 11, 134, 87, 13, 1, 128, 138, 30, 141, 159, 127,
        180, 199, 68, 234, 119, 30, 127, 57, 224, 96, 120, 195, 144, 60, 220, 85, 94, 146, 19, 156, 238, 244, 208, 95, 42, 133, 39, 55, 50, 238, 232, 124, 182, 133, 201, 42, 184,
        171, 217, 180, 191, 91, 104, 196, 209, 63, 67, 108, 72, 166, 132, 247, 65, 164, 84, 157, 54, 68, 125, 8, 51, 122, 88, 23, 192, 127, 247, 112, 44, 190, 221, 136, 135, 248,
        135, 97, 107, 142, 72, 152, 195, 220, 104, 105, 172, 211, 133, 123, 58, 157, 144, 163, 205, 194, 198, 249, 223, 173, 60, 68, 77, 100, 74, 61, 93, 181, 119, 150, 123, 227,
        1, 109, 166, 105, 39, 230, 201, 92, 83, 120, 227, 124, 112, 233, 110, 75, 187, 101, 140, 249, 120, 30, 159, 92, 143, 81, 211, 165, 103, 206, 198, 184, 254, 126, 129, 223,
        215, 56, 225, 230, 198, 72, 44, 22, 232, 81, 91, 192, 145, 133, 234, 108, 0, 82, 12, 90, 150, 150, 56, 181, 216, 91, 61, 255, 232, 137, 232, 146, 209, 110, 194, 172, 189,
        28, 65, 150, 248, 28, 216, 21, 204, 57, 16, 160, 8, 50, 90, 49, 59, 158, 191, 81, 162, 251, 190, 124, 224, 67, 92, 181, 158, 110, 5, 169, 41, 142, 178, 67, 15, 11, 38, 75,
        238, 167, 142, 6, 239, 231, 145, 78, 159, 70, 65, 211, 8, 184, 220, 51, 126, 24, 36, 237, 119, 80, 127, 158, 135, 39, 78, 245, 251, 150, 89, 126, 100, 255, 50, 148, 12,
        226, 216, 108, 189, 245, 176, 121, 122, 64, 247, 161, 182, 253, 247, 141, 144, 5, 214, 28, 186, 93, 165, 73, 32, 20, 191, 191, 81, 171, 171, 193, 163, 213, 180, 139, 63,
        103, 87, 248, 206, 91, 163, 142, 123, 162, 225, 226, 14, 231, 86, 118, 225, 13, 16, 187, 188, 7, 187, 231, 75, 107, 53, 177, 50, 217, 164, 63, 213, 216, 105, 243, 226, 250,
        147, 97, 6, 159, 47, 253, 33, 119, 46, 251, 25, 131, 174, 114, 121, 152, 229, 100, 98, 138, 69, 146, 82, 115, 151, 214, 67, 255, 66, 232, 111, 180, 242, 131, 243, 110, 109,
        239, 37, 222, 81, 176, 169, 5, 181, 114, 117, 252, 202, 143, 22, 245, 111, 173, 185, 166, 84, 97, 128, 240, 82, 189, 43, 183, 178, 49, 249, 52, 180, 175, 165, 121, 113, 217,
        197, 69, 128, 31, 140, 130, 198, 100, 180, 56, 244, 149, 199, 61, 82, 86, 27, 202, 64, 194, 56, 135, 207, 109, 98, 188, 95, 78, 135, 47, 219, 252, 99, 182, 242, 192, 74, 228,
        177, 148, 110, 153, 123, 195, 104, 226, 99, 42, 74, 255, 152, 131, 72, 45, 7, 35, 113, 191, 163, 148, 34, 240, 133, 2, 54, 82, 77, 30, 171, 34, 18, 149, 227, 193, 11, 70, 251,
        83, 98, 243, 249, 218, 243, 139, 66, 156, 27, 14, 125, 167, 165, 22, 90, 32, 98, 209, 111, 198, 92, 194, 73, 15, 255, 26, 243, 61, 208, 154, 148, 84, 170, 196, 199, 173, 14,
        254, 225, 111, 67, 236, 241, 72, 104, 198, 112, 143, 179, 242, 223, 95, 224, 32, 79, 38, 80, 84, 211, 127, 228, 100, 102, 179, 223, 156, 124, 111, 218, 241, 112, 99, 111, 63,
        221, 30, 128, 178, 249, 12, 214, 53, 159, 236, 188, 11, 20, 234, 160, 98, 99, 136, 254, 228, 127, 120, 224, 142, 213, 164, 35, 27, 2, 216, 83, 148, 37, 230, 215, 82, 3, 90,
        251, 19, 123, 155, 137, 203, 164, 168, 59, 133, 225, 58, 79, 56, 212, 99, 124, 152, 57, 32, 147, 139, 217, 152, 168, 49, 233, 68, 110, 36, 64, 48, 168, 109, 221, 38, 107,
        235, 137, 101, 164, 151, 43, 86, 243, 203, 150, 234, 1, 8, 51, 7, 50, 199, 169, 82, 223, 239, 131, 26, 9, 188, 217, 152, 79, 210, 83, 247, 144, 227, 38, 151, 120, 70, 85,
        72, 178, 196, 43, 6, 161, 16, 235, 239, 139, 50, 200, 1, 38, 21, 28, 201, 108, 245, 184, 9, 229, 33, 190, 65, 26, 10, 173, 154, 18, 193, 204, 88, 171, 16, 136, 148, 129,
        213, 118, 14, 100, 229, 5, 196, 126, 55, 79, 200, 29, 194, 146, 250, 167, 88, 223, 167, 115, 207, 104, 95, 255, 54, 254, 9, 165, 101, 25, 123, 120, 96, 231, 16, 69, 44,
        85, 46, 208, 208, 84, 146, 242, 172, 138, 2, 198, 152, 121, 78, 185, 125, 245, 110, 61, 237, 159, 78, 16, 113, 107, 102, 77, 64, 207, 214, 75, 140, 234, 190, 1, 232, 28,
        99, 247, 219, 68, 218, 28, 3, 73, 67, 58, 244, 95, 177, 218, 224, 103, 168, 116, 79, 173, 226, 195, 77, 104, 149, 65, 98, 173, 18, 233, 40, 46, 146, 212, 47, 3, 173, 82,
        152, 177, 226, 24, 47, 202, 29, 64, 187, 1, 160, 99, 207, 32, 92, 44, 85, 127, 138, 111, 217, 134, 48, 88, 125, 217, 0, 203, 167, 136, 237, 227, 106, 128, 159, 159, 165,
        26, 166, 156, 22, 7, 41, 105, 15, 203, 247, 1, 91, 174, 75, 208, 160, 114, 229, 204, 30, 185, 242, 38, 31, 21, 233, 47, 86, 193, 114, 174, 190, 247, 4, 136, 228, 84, 4,
        44, 94, 8, 247, 190, 77, 12, 251, 26, 127, 91, 53, 38, 29, 166, 144, 185, 204, 143, 151, 177, 108, 129, 66, 231, 3, 183, 64, 230, 53, 166, 10, 118, 101, 93, 0, 7, 150,
        18, 6, 197, 237, 142, 63, 231, 171, 196, 162, 81, 143, 187, 182, 104, 255, 221, 2, 37, 17, 167, 74, 201, 21, 135, 204, 239, 192, 211, 195, 159, 111, 140, 142, 199, 120,
        44, 185, 136, 114, 21, 183, 116, 53, 155, 32, 42, 213, 246, 42, 119, 133, 17, 168, 120, 37, 198, 68, 66, 136, 237, 134, 27, 163, 1, 35, 17, 243, 109, 75, 184, 127, 122,
        50, 173, 89, 180, 61, 59, 117, 72, 218, 218, 65, 181, 166, 150, 199, 251, 127, 169, 219, 35, 172, 214, 193, 53, 164, 85, 86, 235, 1, 206, 88, 32, 60, 141, 95, 153, 92,
        188, 254, 93, 186, 29, 148, 111, 110, 185, 52, 200, 41, 206, 30, 132, 8, 175, 5, 34, 85, 237, 40, 27, 177, 90, 23, 98, 40, 56, 236, 162, 144, 218, 212, 71, 188, 66, 36,
        72, 74, 235, 32, 20, 35, 127, 231, 133, 59, 164, 108, 29, 227, 31, 89, 6, 5, 122, 180, 104, 78, 176, 200, 130, 28, 27, 191, 181, 170, 98, 10, 20, 252, 140, 17, 231, 164,
        48, 198, 134, 177, 85, 30, 186, 144, 187, 55, 232, 95, 144, 245, 56, 101, 240, 135, 248, 192, 58, 83, 47, 143, 102, 223, 201, 133, 41, 149, 182, 66, 164, 161, 216, 49,
        143, 133, 99, 142, 41, 105, 223, 75, 72, 158, 228, 161, 212, 228, 187, 252, 77, 156, 153, 131, 68, 250, 195, 21, 139, 217, 207, 127, 158, 87, 181, 191, 171, 88, 71, 28,
        84, 111, 22, 39, 9, 26, 236, 106, 7, 18, 89, 235, 93, 171, 244, 15, 173, 237, 22, 209, 101, 120, 85, 255, 43, 68, 177, 178, 67, 46, 166, 133, 189, 13, 49, 192, 183, 114,
        226, 250, 124, 81, 150, 160, 198, 95, 146, 143, 165, 179, 122, 178, 69, 150, 244, 199, 248, 144, 126, 122, 252, 220, 29, 175, 239, 242, 139, 239, 221, 124, 241, 34, 155,
        129, 57, 155, 223, 131, 76, 131, 181, 53, 154, 81, 114, 195, 9, 110, 209, 140, 113, 223, 231, 223, 161, 99, 214, 15, 10, 71, 58, 185, 151, 101, 169, 29, 54, 28, 43, 52,
        246, 250, 71, 238, 137, 59, 191, 184, 80, 12, 54, 137, 133, 142, 242, 219, 6, 82, 104, 171, 22, 227, 46, 185, 115, 150, 122, 104, 237, 96, 31, 127, 1, 188, 59, 136, 136,
        231, 198, 144, 3, 143, 241, 2, 20, 18, 92, 136, 115, 132, 183, 203, 37, 137, 98, 125, 171, 121, 84, 42, 71, 36, 134, 137, 164, 39, 190, 222, 234, 195, 218, 39, 247, 122,
        14, 227, 153, 3, 61, 184, 120, 9, 195, 115, 116, 4, 76, 100, 23, 151, 61, 161, 248, 252, 176, 129, 166, 252, 3, 250, 151, 35, 203, 13, 2, 154, 72, 20, 150, 125, 26, 86,
        182, 247, 136, 120, 172, 92, 127, 217, 113, 130, 33, 189, 253, 175, 213, 237, 21, 146, 183, 49, 39, 232, 37, 121, 238, 221, 189, 61, 134, 11, 214, 131, 45, 247, 122, 165,
        139, 232, 231, 124, 56, 253, 56, 53, 203, 146, 73, 237, 152, 142, 237, 183, 19, 221, 184, 167, 178, 190, 158, 167, 56, 249, 172, 67, 139, 191, 105, 202, 52, 83, 54, 253,
        234, 93, 100, 3, 103, 43, 249, 128, 190, 53, 255, 127, 32, 173, 232, 4, 155, 106, 174, 232, 128, 9, 217, 128, 96, 107, 26, 18, 39, 117, 86, 9, 7, 231, 205, 216, 221, 157,
        188, 110, 157, 114, 237, 167, 33, 104, 132, 36, 191, 227, 240, 212, 85, 112, 61, 74, 163, 214, 117, 247, 23, 173, 153, 183, 151, 69, 91, 142, 66, 44, 124, 187, 202, 137,
        6, 52, 54, 134, 135, 82, 174, 254, 176, 211, 233, 7, 5, 221, 139, 184, 37, 153, 195, 20, 250, 87, 141, 210, 250, 50, 210, 198, 170, 92, 201, 204, 30, 183, 196, 41, 148,
        97, 22, 29, 43, 234, 153, 8, 137, 196, 246, 239, 49, 84, 151, 106, 91, 218, 198, 228, 7, 99, 0, 30, 190, 70, 164, 21, 48, 93, 33, 220, 150, 71, 6, 189, 53, 42, 100, 110,
        56, 199, 27, 80, 190, 85, 6, 218, 24, 117, 212, 102, 170, 98, 97, 123, 227, 153, 248, 7, 159, 0, 63, 70, 17, 100, 233, 238, 28, 123, 124, 104, 71, 248, 154, 131, 12, 20,
        220, 37, 153, 5, 147, 95, 184, 217, 99, 89, 232, 238, 91, 108, 241, 135, 196, 80, 229, 36, 67, 245, 128, 148, 150, 220, 113, 79, 42, 255, 92, 104, 12, 144, 235, 248,
        157, 100, 191, 160, 164, 137, 122, 222, 116, 78, 233, 32, 239, 113, 114, 21, 244, 215, 121, 207, 118, 245, 18, 7, 38, 115, 221, 87, 99, 141, 231, 169, 121, 81, 230,
        40, 78, 223, 64, 234, 15, 163, 32, 115, 79, 124, 66, 3, 209, 204, 96, 30, 50, 150, 82, 51, 136, 13, 252, 122, 116, 220, 99, 171, 253, 182, 192, 162, 156, 196, 13, 208,
        127, 178, 132, 12, 117, 144, 227, 9, 152, 214, 251, 181, 48, 118, 158, 12, 183, 131, 6, 56, 68, 87, 246, 134, 65, 3, 119, 125, 88, 86, 25, 15, 13, 251, 100, 109, 62,
        143, 116, 188, 22, 36, 154, 13, 44, 122, 72, 221, 30, 64, 124, 219, 20, 207, 4, 68, 171, 161, 29, 151, 210, 47, 234, 69, 140, 147, 18, 25, 138, 219, 84, 61, 46, 194,
        30, 4, 23, 61, 209, 87, 123, 201, 169, 22, 86, 107, 26, 196, 212, 1, 92, 180, 121, 239, 20, 109, 223, 170, 143, 86, 116, 220, 61, 58, 223, 3, 225, 163, 229, 242, 193,
        202, 75, 38, 143, 140, 33, 64, 27, 50, 61, 97, 59, 95, 215, 32, 56, 170, 124, 231, 47, 175, 240, 59, 181, 96, 179, 56, 164, 165, 24, 84, 6, 151, 168, 143, 121, 230,
        216, 36, 245, 211, 65, 78, 162, 125, 149, 118, 209, 92, 176, 33, 47, 118, 236, 227, 20, 107, 21, 97, 189, 218, 130, 197, 212, 217, 128, 77, 31, 102, 77, 192, 240, 70,
        165, 2, 178, 221, 87, 203, 20, 168, 249, 190, 242, 182, 15, 216, 86, 178, 252, 84, 192, 151, 131, 83, 75, 6, 236, 238, 47, 58, 194, 201, 192, 46, 191, 167, 206, 155,
        49, 37, 2, 177, 235, 166, 7, 114, 130, 235, 209, 153, 240, 48, 93, 46, 53, 39, 4, 208, 71, 170, 159, 155, 91, 134, 20, 191, 199, 135, 85, 22, 202, 94, 155, 102, 150,
        248, 205, 79, 99, 119, 139, 75, 197, 26, 34, 18, 179, 134, 185, 158, 101, 228, 52, 88, 33, 7, 224, 64, 44, 44, 151, 111, 43, 253, 242, 226, 231, 154, 132, 172, 160,
        143, 143, 86, 13, 69, 226, 149, 215, 44, 252, 15, 119, 157, 252, 80, 221, 162, 214, 226, 213, 89, 56, 29, 127, 161, 105, 18, 127, 140, 255, 149, 23, 227, 148, 129,
        179, 59, 143, 47, 127, 53, 83, 202, 142, 126, 248, 184, 1, 151, 54, 19, 40, 163, 240, 242, 133, 184, 30, 202, 210, 171, 55, 133, 18, 222, 67, 41, 191, 138, 154, 62,
        141, 98, 174, 3, 213, 33, 176, 157, 86, 164, 172, 12, 21, 104, 160, 46, 209, 190, 50, 184, 28, 250, 145, 103, 88, 250, 0, 222, 154, 148, 111, 170, 50, 246, 136, 133,
        162, 47, 187, 38, 235, 198, 249, 51, 206, 92, 118, 14, 73, 253, 172, 222, 130, 212, 106, 97, 72, 122, 138, 56, 116, 184, 98, 7, 35, 131, 73, 231, 12, 83, 189, 97, 174,
        94, 200, 20, 58, 89, 100, 171, 109, 102, 61, 130, 146, 223, 53, 121, 12, 45, 210, 248, 134, 78, 71, 28, 234, 109, 172, 145, 21, 26, 30, 159, 203, 118, 6, 178, 84, 45,
        126, 219, 166, 190, 187, 76, 14, 148, 39, 159, 96, 190, 22, 218, 103, 62, 1, 99, 243, 82, 43, 112, 74, 232, 193, 143, 43, 81, 222, 138, 93, 71, 252, 7, 251, 148, 66, 74, 168, 216, 21, 240, 81, 56, 183, 152, 23, 102, 27, 154, 207, 32, 102, 69, 58, 144, 215, 99, 182, 112, 75, 18, 117, 22, 109, 86, 213, 171, 41, 152, 115, 140, 195, 52, 4, 169, 200, 43, 236, 8, 220, 21, 165, 188, 149, 110, 216, 122, 7, 205, 44, 48, 185, 184, 165, 181, 71, 163, 113, 224, 12, 181, 121, 232, 38, 172, 40, 238, 236, 207, 237, 193, 211, 156, 77, 72, 131, 13, 12, 158, 73, 111, 238, 220, 80, 33, 170, 188, 45, 203, 59, 222, 252, 65, 206, 2, 102, 221, 117, 234, 179, 187, 214, 250, 152, 36, 28, 25, 194, 108, 18, 177, 165, 32, 249, 67, 237, 120, 147, 208, 20, 255, 179, 244, 176, 111, 127, 20, 238, 237, 175, 199, 139, 133, 225, 158, 101, 204, 133, 124, 127, 134, 75, 15, 200, 8, 248, 123, 232, 244, 8, 150, 225, 206, 225, 82, 139, 105, 198, 214, 136, 81, 32, 215, 139, 25, 61, 7, 21, 54, 61, 126, 45, 94, 131, 68, 145, 9, 59, 5, 135, 131, 6, 248, 251, 163, 194, 194, 99, 89, 80, 123, 123, 45, 139, 165, 162, 22, 28, 50, 236, 230, 28, 127, 167, 219, 31, 154, 176, 27, 63, 215, 29, 222, 9, 38, 19, 90, 72, 137, 22, 159, 98, 33, 5, 14, 38, 232, 140, 154, 220, 68, 70, 21, 22, 171, 153, 216, 204, 196, 133, 115, 138, 81, 122, 79, 139, 86, 205, 194, 83, 199, 251, 210, 118, 141, 213, 219, 25, 227, 119, 181, 105, 36, 212, 158, 50, 12, 133, 118, 244, 191, 193, 230, 151, 245, 161, 23, 108, 197, 60, 173, 95, 131, 255, 70, 223, 131, 205, 45, 16, 136, 19, 143, 21, 109, 174, 127, 52, 69, 192, 244, 135, 77, 67, 182, 88, 133, 241, 254, 155, 118, 80, 218, 135, 111, 2, 106, 0, 82, 156, 156, 137, 20, 46, 30, 221, 3, 165, 108, 202, 58, 64, 210, 80, 235, 155, 57, 187, 188, 29, 4, 107, 58, 243, 192, 10, 197, 20, 60, 71, 201, 101, 74, 229, 202, 178, 32, 150, 174, 54, 50, 74, 105, 90, 191, 3, 179, 62, 224, 128, 197, 124, 123, 80, 112, 200, 231, 68, 206, 229, 14, 24, 83, 137, 181, 128, 173, 224, 197, 94, 124, 91, 5, 11, 106, 213, 79, 189, 255, 121, 156, 22, 161, 203, 117, 203, 29, 173, 80, 107, 88, 60, 65, 5, 53, 211, 96, 27, 199, 60, 1, 60, 0, 27, 186, 45, 185, 247, 45, 223, 167, 109, 10, 106, 67, 68, 225, 53, 59, 123, 17, 89, 97, 27, 232, 129, 135, 178, 124, 142, 126, 58, 178, 156, 229, 132, 151, 33, 2, 197, 164, 0, 119, 118, 38, 213, 13, 238, 172, 126, 241, 219, 44, 89, 98, 218, 208, 209, 243, 56, 0, 128, 10, 218, 108, 111, 169, 39, 166, 17, 177, 82, 237, 185, 222, 28, 139, 223, 223, 216, 233, 227, 86, 164, 15, 138, 195, 76, 231, 183, 56, 210, 252, 153, 64, 23, 246, 200, 108, 33, 35, 174, 93, 52, 167, 105, 91, 11, 199, 53, 188, 12, 171, 253, 184, 29, 147, 79, 237, 43, 69, 220, 227, 144, 82, 3, 249, 17, 37, 249, 207, 250, 145, 148, 78, 172, 4, 59, 89, 123, 128, 38, 172, 75, 111, 120, 107, 39, 69, 17, 246, 4, 146, 142, 201, 132, 63, 176, 237, 120, 143, 223, 110, 96, 54, 214, 82, 43, 254, 169, 191, 87, 61, 44, 119, 140, 225, 47, 83, 130, 234, 179, 93, 182, 119, 77, 8, 122, 107, 89, 46, 150, 208, 86, 170, 149, 154, 210, 138, 81, 0, 203, 166, 118, 147, 107, 148, 103, 174, 220, 142, 106, 101, 214, 81, 35, 244, 40, 236, 224, 228, 102, 81, 233, 84, 68, 217, 30, 147, 95, 8, 248, 82, 235, 15, 197, 200, 42, 77, 76, 140, 130, 220, 152, 196, 50, 242, 134, 109, 70, 92, 136, 24, 1, 86, 98, 178, 254, 199, 118, 103, 131, 218, 91, 232, 6, 24, 147, 138, 175, 22, 217, 46, 105, 56, 90, 224, 61, 153, 95, 134, 48, 114, 143, 151, 86, 144, 243, 255, 83, 81, 97, 90, 234, 3, 224, 112, 12, 3, 164, 121, 79, 118, 125, 76, 106, 32, 123, 69, 48, 131, 113, 79, 52, 210, 246, 41, 110, 92, 78, 112, 148, 232, 116, 1, 93, 106, 101, 216, 157, 192, 172, 53, 229, 2, 92, 247, 102, 27, 71, 192, 195, 200, 92, 121, 88, 130, 21, 218, 199, 210, 76, 200, 122, 109, 240, 246, 81, 128, 58, 19, 175, 234, 28, 228, 92, 68, 162, 14, 170, 122, 128, 71, 53, 71, 13, 114, 14, 97, 111, 83, 121, 230, 95, 167, 231, 223, 125, 153, 92, 204, 80, 97, 82, 202, 83, 117, 28, 133, 114, 231, 222, 245, 36, 235, 9, 126, 61, 240, 16, 20, 169, 115, 55, 231, 230, 152, 122, 92, 47, 69, 246, 74, 237, 165, 170, 105, 158, 16, 67, 97, 157, 147, 15, 68, 85, 20, 101, 159, 143, 35, 80, 20, 206, 30, 180, 150, 170, 8, 9, 158, 34, 150, 126, 147, 125, 146, 44, 83, 115, 73, 96, 207, 180, 26, 111, 226, 105, 167, 167, 237, 87, 136, 82, 194, 175, 149, 197, 26, 244, 11, 202, 204, 106, 78, 167, 238, 203, 15, 188, 230, 197, 192, 241, 135, 12, 40, 145, 155, 115, 176, 76, 211, 157, 63, 231, 184, 44, 70, 67, 222, 130, 222, 31, 147, 144, 171, 42, 204, 61, 190, 104, 140, 8, 25, 95, 190, 218, 35, 204, 193, 99, 19, 189, 183, 240, 58, 218, 121, 181, 60, 81, 125, 118, 98, 39, 223, 96, 210, 21, 156, 250, 229, 4, 149, 86, 24, 7, 129, 33, 213, 52, 160, 8, 19, 95, 148, 37, 245, 45, 104, 170, 135, 40, 225, 244, 42, 86, 136, 154, 243, 55, 122, 173, 115, 195, 144, 254, 77, 26, 52, 13, 195, 112, 172, 10, 80, 57, 200, 69, 184, 99, 204, 172, 67, 104, 45, 215, 194, 208, 25, 119, 222, 138, 181, 210, 98, 192, 157, 36, 157, 231, 150, 19, 2, 105, 51, 138, 68, 236, 58, 134, 101, 8, 194, 101, 41, 215, 7, 181, 207, 57, 62, 167, 143, 8, 204, 61, 165, 207, 55, 156, 49, 164, 230, 116, 40, 42, 95, 162, 240, 126, 103, 25, 14, 22, 49, 47, 76, 79, 158, 117, 192, 47, 37, 190, 66, 128, 197, 172, 189, 13, 8, 30, 62, 29, 56, 149, 12, 14, 71, 39, 42, 206, 120, 96, 106, 41, 213, 252, 83, 229, 235, 172, 65, 69, 140, 13, 226, 56, 30, 252, 229, 204, 37, 152, 173, 20, 24, 49, 75, 175, 230, 130, 29, 62, 23, 18, 10, 194, 60, 189, 238, 49, 50, 41, 246, 176, 115, 12, 53, 69, 213, 82, 100, 174, 40, 7, 118, 8, 135, 205, 165, 222, 122, 28, 98, 84, 24, 37, 180, 44, 80, 127, 219, 138, 76, 190, 118, 145, 64, 67, 193, 252, 198, 69, 148, 127, 204, 64, 62, 191, 220, 251, 97, 111, 197, 12, 41, 71, 85, 243, 197, 198, 114, 253, 52, 134, 71, 202, 2, 182, 146, 57, 23, 147, 181, 71, 131, 146, 148, 212, 174, 57, 192, 216, 95, 47, 81, 72, 25, 2, 230, 219, 38, 68, 225, 103, 115, 227, 17, 120, 58, 193, 50, 48, 17, 96, 204, 169, 173, 46, 156, 30, 123, 52, 16, 0, 31, 47, 109, 148, 183, 194, 243, 203, 71, 196, 202, 84, 233, 140, 102, 88, 107, 56, 35, 206, 134, 55, 210, 133, 76, 88, 125, 21, 127, 6, 139, 155, 135, 164, 49, 14, 52, 192, 90, 100, 172, 86, 210, 152, 98, 7, 32, 227, 157, 98, 106, 188, 38, 2, 225, 156, 164, 6, 86, 217, 158, 226, 199, 23, 48, 95, 136, 69, 35, 6, 51, 115, 204, 219, 105, 148, 175, 54, 216, 165, 205, 200, 212, 114, 192, 254, 175, 57, 142, 23, 44, 124, 237, 23, 204, 251, 173, 115, 185, 76, 50, 57, 4, 147, 36, 220, 217, 154, 139, 21, 254, 127, 200, 42, 181, 252, 98, 132, 82, 218, 210, 244, 237, 217, 40, 193, 207, 231, 214, 138, 119, 182, 120, 166, 199, 39, 2, 119, 32, 45, 126, 92, 97, 128, 81, 157, 229, 184, 69, 54, 98, 133, 156, 148, 204, 158, 133, 89, 198, 110, 209, 118, 151, 16, 80, 220, 245, 74, 145, 252, 47, 21, 180, 36, 205, 49, 97, 73, 71, 209, 166, 60, 246, 55, 174, 158, 79, 12, 187, 244, 189, 61, 230, 191, 170, 11, 228, 48, 123, 251, 27, 107, 120, 122, 55, 8, 158, 146, 239, 235, 255, 191, 84, 214, 11, 217, 196, 162, 231, 239, 22, 143, 125, 91, 253, 241, 229, 81, 132, 94, 60, 247, 19, 1, 62, 77, 25, 17, 214, 109, 100, 78, 244, 50, 85, 193, 26, 119, 67, 121, 249, 197, 53, 72, 63, 125, 198, 117, 91, 157, 85, 29, 150, 70, 105, 139, 216, 10, 21, 182, 241, 2, 73, 34, 4, 194, 165, 32, 22, 22, 121, 103, 13, 185, 137, 99, 238, 85, 7, 199, 184, 77, 111, 49, 84, 213, 200, 176, 179, 117, 98, 14, 23, 13, 90, 191, 76, 127, 199, 95, 165, 124, 122, 94, 194, 214, 55, 196, 33, 73, 1, 204, 44, 230, 47, 61, 163, 213, 252, 169, 49, 229, 58, 2, 7, 240, 57, 19, 160, 158, 168, 226, 63, 194, 170, 17, 207, 177, 23, 84, 117, 62, 75, 232, 53, 83, 233, 202, 227, 18, 63, 91, 146, 244, 158, 174, 68, 85, 43, 239, 238, 91, 63, 189, 218, 17, 144, 98, 195, 57, 128, 12, 165, 162, 146, 169, 116, 75, 13, 54, 3, 134, 138, 201, 238, 249, 48, 233, 87, 151, 177, 210, 84, 89, 35, 30, 125, 250, 164, 226, 141, 82, 42, 99, 231, 80, 79, 180, 71, 138, 73, 18, 180, 159, 246, 254, 213, 21, 221, 191, 247, 120, 220, 186, 157, 95, 18, 66, 65, 112, 178, 102, 46, 58, 249, 115, 34, 241, 136, 16, 250, 147, 156, 225, 0, 9, 174, 164, 29, 1, 211, 161, 63, 154, 237, 51, 3, 109, 158, 75, 211, 185, 69, 227, 107, 114, 96, 212, 141, 64, 73, 20, 210, 155, 186, 124, 231, 74, 115, 126, 89, 152, 43, 73, 136, 234, 11, 241, 74, 27, 229, 63, 23, 3, 3, 0, 95, 89, 64, 108, 25, 166, 213, 253, 250, 2, 157, 248, 205, 13, 149, 255, 44, 167, 37, 90, 124, 142, 215, 111, 0, 98, 48, 150, 43, 137, 235, 91, 31, 108, 9, 126, 119, 127, 117, 219, 115, 152, 156, 184, 25, 245, 204, 153, 135, 204, 145, 58, 104, 219, 210, 167, 232, 45, 240, 93, 148, 218, 36, 187, 98, 151, 187, 17, 21, 171, 50, 140, 49, 109, 253, 85, 96, 44, 105, 178, 17, 152, 33, 225, 170, 224, 86, 254, 208, 195, 76, 128, 205, 143, 34, 83, 23, 3, 3, 2, 23, 186, 202, 83, 55, 134, 174, 61, 68, 239, 49, 249, 71, 218, 76, 230, 61, 174, 100, 224, 108, 77, 6, 83, 113, 84, 52, 158, 232, 214, 241, 101, 156, 251, 234, 119, 247, 48, 41, 148, 168, 191, 24, 63, 70, 77, 169, 115, 25, 66, 249, 62, 210, 192, 98, 195, 87, 152, 194, 100, 62, 194, 234, 129, 15, 186, 55, 241, 10, 220, 116, 162, 182, 150, 107, 169, 168, 62, 62, 232, 147, 67, 68, 0, 59, 56, 123, 105, 18, 53, 83, 13, 214, 63, 35, 108, 149, 124, 107, 35, 182, 146, 198, 193, 20, 176, 203, 16, 195, 3, 103, 50, 162, 57, 35, 9, 227, 59, 141, 79, 72, 160, 14, 81, 244, 240, 152, 161, 46, 44, 128, 2, 119, 233, 218, 162, 220, 239, 136, 121, 84, 20, 246, 189, 231, 54, 18, 102, 168, 117, 250, 124, 100, 151, 220, 53, 201, 46, 174, 201, 185, 113, 109, 243, 83, 62, 108, 209, 168, 9, 252, 227, 83, 5, 181, 21, 198, 244, 163, 227, 237, 169, 38, 186, 82, 132, 150, 80, 43, 237, 12, 36, 246, 20, 13, 55, 131, 145, 96, 147, 248, 208, 77, 69, 58, 230, 53, 224, 218, 29, 239, 204, 136, 101, 183, 174, 41, 222, 113, 2, 210, 230, 150, 59, 143, 42, 133, 60, 229, 11, 129, 240, 23, 107, 207, 132, 158, 205, 245, 154, 139, 116, 156, 36, 128, 154, 47, 63, 175, 254, 99, 200, 6, 226, 188, 208, 39, 100, 186, 70, 88, 98, 165, 112, 77, 78, 137, 182, 22, 141, 83, 211, 48, 197, 67, 116, 103, 191, 201, 151, 197, 204, 3, 165, 218, 147, 69, 81, 234, 239, 162, 99, 76, 103, 106, 27, 30, 83, 143, 206, 236, 36, 203, 121, 96, 42, 65, 205, 187, 89, 163, 86, 110, 228, 68, 179, 188, 124, 64, 127, 251, 114, 220, 66, 55, 24, 194, 188, 202, 210, 6, 99, 121, 68, 115, 116, 190, 174, 140, 35, 237, 213, 148, 25, 215, 16, 90, 154, 49, 32, 52, 3, 112, 136, 64, 41, 3, 38, 82, 5, 79, 128, 209, 86, 180, 125, 39, 45, 251, 136, 252, 199, 79, 171, 209, 9, 49, 116, 83, 10, 89, 126, 86, 69, 248, 42, 82, 206, 199, 198, 202, 24, 151, 234, 37, 249, 153, 36, 58, 54, 102, 47, 111, 38, 50, 118, 161, 70, 141, 64, 237, 182, 64, 67, 11, 249, 168, 176, 173, 149, 236, 238, 160, 237, 114, 75, 111, 237, 203, 242, 135, 30, 20, 227, 205, 9, 30, 27, 242, 157, 12, 12, 44, 145, 144, 124, 1, 97, 110, 72, 210, 139, 105, 225, 8, 182, 98, 88, 246, 160, 42, 7, 228, 111, 179, 66, 199, 115, 140, 105, 3, 187, 157, 1, 176, 241, 51, 88, 38, 138, 148, 20, 31, 61, 211, 117, 251, 31, 117, 140, 220, 175, 87, 23, 20, 228, 100, 169, 52, 124, 204, 96, 22, 108, 40, 54, 127, 206, 233, 99, 37, 168, 107, 214, 10, 158, 124, 123, 94, 96, 152, 154, 176, 172, 48, 176, 235, 47, 129, 167, 137, 108, 167, 170, 19, 207, 23, 3, 3, 5, 127, 235, 221, 28, 131, 32, 233, 227, 3, 199, 245, 208, 57, 76, 70, 174, 56, 21, 92, 3, 244, 49, 105, 164, 168, 110, 174, 94, 142, 189, 183, 92, 225, 73, 35, 133, 223, 254, 131, 9, 236, 101, 245, 131, 61, 193, 253, 166, 178, 203, 153, 59, 108, 141, 147, 40, 149, 8, 103, 55, 42, 210, 145, 92, 72, 94, 190, 200, 239, 191, 170, 29, 113, 175, 48, 31, 1, 20, 135, 182, 198, 152, 160, 195, 141, 255, 229, 5, 202, 246, 28, 194, 22, 149, 162, 158, 153, 161, 61, 98, 167, 153, 50, 102, 86, 21, 169, 120, 193, 91, 115, 84, 149, 158, 23, 204, 34, 27, 124, 65, 3, 193, 136, 212, 248, 225, 231, 77, 132, 185, 160, 174, 234, 44, 171, 234, 199, 230, 57, 51, 224, 90, 113, 147, 211, 194, 226, 168, 182, 41, 39, 51, 180, 160, 200, 69, 225, 114, 4, 191, 118, 161, 186, 184, 175, 111, 203, 134, 227, 202, 73, 71, 203, 17, 175, 161, 0, 228, 95, 71, 255, 123, 197, 19, 211, 211, 68, 225, 76, 57, 14, 184, 12, 208, 240, 20, 84, 146, 37, 201, 220, 119, 231, 53, 108, 87, 220, 21, 157, 10, 32, 206, 31, 87, 53, 17, 121, 167, 41, 67, 96, 21, 158, 159, 26, 226, 95, 114, 4, 39, 102, 63, 229, 159, 235, 244, 186, 200, 220, 105, 64, 129, 1, 219, 109, 229, 189, 119, 128, 145, 42, 37, 44, 159, 211, 124, 224, 36, 198, 103, 56, 144, 41, 13, 230, 89, 127, 193, 10, 247, 53, 15, 208, 236, 177, 64, 160, 130, 108, 48, 179, 34, 27, 36, 16, 203, 157, 189, 201, 175, 242, 60, 235, 247, 6, 88, 146, 38, 64, 161, 245, 242, 89, 55, 194, 106, 209, 53, 233, 244, 250, 242, 37, 244, 16, 214, 71, 204, 215, 145, 195, 104, 168, 157, 90, 81, 228, 111, 124, 62, 8, 248, 170, 167, 190, 4, 112, 66, 28, 67, 199, 72, 86, 181, 197, 2, 57, 213, 124, 124, 56, 244, 200, 151, 82, 192, 2, 102, 11, 124, 223, 226, 223, 215, 40, 158, 154, 184, 128, 240, 137, 95, 50, 106, 207, 232, 62, 196, 141, 57, 68, 44, 131, 185, 173, 255, 93, 100, 82, 100, 1, 89, 179, 36, 150, 209, 134, 243, 147, 203, 145, 225, 100, 235, 158, 171, 63, 122, 131, 160, 97, 158, 159, 47, 187, 23, 62, 52, 178, 120, 165, 188, 24, 143, 121, 183, 237, 67, 228, 145, 109, 14, 196, 233, 80, 88, 10, 68, 14, 58, 51, 207, 161, 109, 78, 77, 141, 253, 233, 5, 180, 164, 97, 127, 185, 100, 199, 120, 5, 27, 201, 77, 127, 148, 159, 141, 37, 11, 210, 48, 227, 69, 122, 79, 6, 119, 50, 149, 22, 183, 65, 109, 181, 156, 123, 65, 120, 242, 185, 115, 79, 172, 96, 150, 244, 3, 233, 162, 3, 190, 186, 125, 151, 74, 66, 93, 49, 246, 79, 196, 230, 77, 11, 82, 31, 143, 180, 143, 106, 127, 183, 22, 202, 12, 28, 205, 185, 158, 4, 83, 205, 88, 241, 235, 254, 202, 181, 220, 203, 73, 3, 17, 36, 104, 60, 185, 189, 167, 41, 110, 16, 28, 216, 4, 112, 253, 249, 105, 41, 157, 170, 146, 91, 235, 81, 234, 151, 253, 121, 158, 44, 170, 145, 249, 110, 211, 116, 19, 81, 211, 88, 186, 42, 41, 35, 57, 123, 193, 207, 231, 174, 124, 231, 16, 50, 36, 126, 129, 238, 13, 116, 200, 201, 35, 22, 156, 194, 145, 218, 159, 195, 159, 78, 240, 233, 249, 208, 184, 255, 239, 143, 141, 40, 35, 131, 189, 114, 183, 63, 202, 184, 31, 206, 19, 244, 165, 241, 16, 32, 67, 1, 245, 153, 240, 209, 159, 126, 212, 171, 77, 238, 164, 211, 189, 160, 215, 84, 170, 255, 44, 124, 251, 197, 3, 120, 69, 90, 146, 218, 176, 163, 205, 88, 25, 166, 25, 250, 134, 218, 127, 11, 221, 145, 77, 23, 42, 127, 230, 226, 122, 143, 10, 151, 100, 46, 211, 240, 123, 241, 99, 236, 170, 228, 64, 176, 63, 233, 103, 220, 82, 178, 54, 88, 241, 23, 86, 193, 233, 154, 142, 110, 214, 59, 6, 197, 218, 183, 5, 54, 129, 117, 242, 218, 214, 60, 68, 122, 181, 10, 77, 175, 19, 207, 94, 111, 159, 41, 51, 173, 70, 150, 203, 113, 79, 82, 28, 194, 29, 232, 44, 117, 25, 112, 5, 142, 171, 174, 79, 177, 75, 94, 181, 154, 115, 121, 92, 180, 64, 229, 167, 192, 239, 124, 113, 135, 79, 3, 104, 245, 87, 82, 0, 139, 210, 193, 60, 64, 169, 3, 184, 42, 213, 20, 120, 201, 166, 164, 127, 171, 141, 153, 169, 160, 61, 252, 18, 22, 241, 171, 143, 191, 162, 89, 141, 125, 108, 228, 253, 186, 244, 178, 204, 141, 76, 189, 59, 3, 195, 115, 75, 94, 37, 83, 94, 0, 42, 175, 34, 53, 123, 149, 209, 200, 20, 42, 252, 223, 70, 71, 26, 204, 10, 2, 168, 177, 65, 254, 192, 70, 59, 113, 134, 13, 74, 209, 231, 211, 248, 218, 191, 10, 175, 138, 198, 230, 95, 175, 128, 237, 146, 41, 227, 88, 185, 75, 218, 239, 44, 183, 21, 231, 225, 101, 50, 32, 53, 31, 98, 37, 204, 50, 8, 254, 5, 212, 114, 141, 43, 62, 196, 16, 196, 201, 253, 253, 210, 163, 228, 95, 32, 140, 156, 217, 248, 41, 189, 194, 148, 10, 176, 194, 80, 192, 241, 27, 148, 48, 64, 192, 56, 90, 156, 52, 127, 248, 253, 9, 97, 24, 52, 75, 234, 93, 190, 46, 147, 19, 160, 209, 138, 255, 179, 48, 149, 233, 169, 43, 198, 141, 195, 12, 211, 117, 126, 104, 217, 100, 218, 115, 226, 120, 205, 69, 250, 90, 144, 212, 5, 85, 120, 53, 128, 184, 44, 77, 2, 209, 137, 28, 17, 141, 128, 132, 218, 98, 162, 181, 179, 166, 163, 93, 108, 244, 4, 52, 116, 129, 234, 92, 137, 207, 238, 75, 26, 170, 158, 24, 225, 159, 130, 80, 43, 133, 51, 137, 46, 150, 50, 182, 155, 232, 10, 126, 88, 162, 25, 176, 210, 94, 47, 46, 118, 65, 146, 9, 102, 185, 118, 174, 161, 74, 208, 240, 138, 76, 178, 240, 60, 121, 66, 234, 215, 195, 12, 47, 53, 232, 211, 110, 187, 7, 97, 253, 227, 145, 55, 80, 117, 50, 201, 23, 225, 228, 190, 239, 147, 81, 222, 182, 213, 93, 7, 58, 80, 30, 8, 238, 247, 14, 146, 77, 191, 184, 85, 7, 62, 89, 134, 190, 28, 255, 15, 168, 115, 189, 42, 193, 125, 214, 124, 233, 128, 156, 39, 129, 10, 205, 147, 212, 2, 227, 78, 65, 138, 0, 178, 247, 180, 92, 185, 0, 228, 177, 219, 22, 218, 183, 253, 132, 100, 6, 57, 46, 61, 31, 49, 50, 148, 66, 172, 63, 131, 191, 207, 26, 233, 241, 131, 52, 214, 247, 141, 172, 191, 136, 68, 3, 113, 152, 219, 156, 44, 171, 24, 13, 209, 89, 81, 126, 42, 25, 217, 210, 213, 126, 187, 152, 129, 215, 125, 105, 3, 218, 24, 245, 214, 161, 33, 250, 81, 178, 158, 209, 205, 150, 118, 47, 92, 83, 61, 202, 25, 15, 183, 51, 151, 154, 60, 208, 33, 93, 180, 99, 23, 243, 91, 142, 170, 40, 138, 192, 125, 181, 230, 75, 232, 254, 26, 176, 1, 244, 8, 58, 180, 52, 108, 93, 14, 100, 161, 233, 8, 254, 251, 49, 217, 107, 116, 52, 19, 241, 62, 63, 14, 33, 252, 86, 83, 10, 86, 17, 62, 56, 118, 108, 245, 119, 193, 80, 10, 234, 25, 2, 73, 13, 119, 124, 95, 132, 24, 69, 73, 93, 48, 222, 226, 76, 182, 50, 211, 105, 163, 137, 147, 63, 66, 44, 240, 72, 21, 53, 92, 80, 226, 65, 125, 82, 38, 76, 32, 237, 34, 121, 18, 211, 193, 45, 152, 152, 2, 236, 103, 188, 168, 195, 230, 81, 86, 132, 64, 253, 71, 71, 193, 97, 21, 239, 82, 108, 254, 116, 3, 238, 4, 98, 122, 46, 211, 242, 159, 213, 248, 234, 248, 231, 24, 154, 237, 141, 140, 176, 182, 167, 26, 48, 12, 170, 169, 23, 3, 3, 0, 184, 95, 196, 152, 33, 217, 109, 45, 99, 185, 126, 154, 161, 156, 126, 49, 9, 229, 132, 133, 246, 151, 155, 189, 76, 211, 133, 31, 44, 158, 131, 196, 130, 100, 101, 192, 193, 167, 134, 82, 71, 237, 146, 192, 171, 58, 122, 123, 25, 221, 10, 139, 68, 41, 39, 125, 247, 238, 71, 211, 141, 111, 161, 77, 89, 132, 62, 131, 187, 146, 9, 59, 175, 91, 15, 124, 51, 39, 33, 61, 140, 69, 35, 104, 104, 226, 210, 185, 82, 123, 77, 140, 157, 192, 187, 246, 255, 208, 34, 47, 5, 144, 154, 88, 238, 94, 43, 102, 237, 200, 54, 220, 24, 223, 202, 249, 173, 122, 237, 40, 31, 79, 210, 19, 4, 19, 33, 11, 15, 33, 31, 173, 29, 126, 84, 196, 53, 117, 51, 225, 0, 19, 207, 227, 116, 91, 47, 130, 60, 145, 34, 176, 99, 159, 51, 246, 245, 128, 204, 239, 73, 92, 198, 61, 186, 238, 222, 117, 99, 197, 18, 27, 166, 136, 229, 137, 187, 207, 216, 236, 217, 130, 175, 74, 117];

    let check_result = Session::check_serialized_session(serialized_tls.to_vec());
    assert_eq!(check_result, true);
}*/