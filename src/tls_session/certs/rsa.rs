//use core::slice::SlicePattern;
use num_bigint::{BigInt, BigUint, ToBigInt, Sign};
use num_traits::Zero;
//use std::error::Error;
//use std::fmt;

/*
struct Modulus {
    nat: Nat,
    leading: usize,
    m0inv: usize,
    rr: Vec<u8>,
}

impl Modulus {
    // fn new_modulus_from_big(n: &BigUint) -> Result<Modulus, Box<dyn Error>> {
    fn new_modulus_from_big(n: &BigInt) -> Option<Modulus> {
        if n.is_zero() {
            return None; //return Err("modulus must be >= 0".into());
        } else if n.is_even() {
            return None; //return Err("modulus must be odd".into());
        }

        let mut m = Modulus {
            nat: Nat::new().set_big(n),
            leading: 0, // Placeholder value
            m0inv: 0,   // Placeholder value
            rr: vec![], // Placeholder for "rr"
        };

        m.leading = std::mem::size_of::<usize>() * 8 - bit_len(&m.nat.limbs[m.nat.limbs.len() - 1]);
        m.m0inv = minus_inverse_mod_w(&m.nat.limbs[0]);
        m.rr = rr(&m);
        Some(m) // Ok(m)
    }
}

fn mod_exp(base: &BigInt, exponent: &BigInt, modulus: &BigInt) -> BigInt {
    base.modpow(exponent, modulus)
}*/

#[derive(Debug)]
pub struct PublicKey {
    pub n: BigInt, // modulus
    pub e: i64, // public exponent
}

impl PublicKey {
    pub fn size(&self) -> usize {
        (self.n.bits() + 7) / 8
    }

    pub fn equal(&self, other: &PublicKey) -> bool {
        &self.n == &other.n && self.e == other.e
    }
}

#[derive(Debug)]
pub struct OAEPOptions {
    hash: String, // Placeholder for crypto hash type
    mgf_hash: String, // Placeholder for MGF hash type
    label: Vec<u8>,
}

// pub fn check_pub(pub_key: &PublicKey) -> Result<(), Box<dyn Error>> {
pub fn check_pub(pub_key: &PublicKey) -> bool {

    if pub_key.n.is_zero() {
        return false; //return Err(Box::new(PublicModulusError));
    }
    if pub_key.e < 2 {
        return false; //return Err(Box::new(PublicExponentSmallError));
    }
    if pub_key.e > ( (1u64 << 31) - 1) as i64 {
        return false; //return Err(Box::new(PublicExponentLargeError));
    }
    true //Ok(())
}

// fn encrypt(pubkey: *PublicKey, plaintext: &[u8]) -> ([]byte, error) {
fn encrypt(pubkey: &PublicKey, plaintext: &[u8]) -> Vec<u8> {

    //let n = Modulus::new_modulus_from_big(&pub_key.n)?; // N, err := bigmod.NewModulusFromBig(pub.N)
    // if err != nil {
    // 		return nil, err
    // 	}
    //let m = Nat::new().set_bytes(plaintext, &n)?; // m, err := bigmod.NewNat().SetBytes(plaintext, N)

    // if err != nil {
    // 		return nil, err
    // 	}
    //let e = pub_key.e as u32; // e := uint(pub.E)


    //let result = Nat::new().exp_short_var_time(&m, e, &n);
    //result.bytes(&n) // Ok(result.bytes(&n)) //return bigmod.NewNat().ExpShortVarTime(m, e, N).Bytes(N), nil

    let base = BigInt::from_bytes_be(Sign::Plus, &plaintext);
    let modulus = &pubkey.n;
    let exponent = BigInt::from(pubkey.e.clone());

    let result = base.modpow(&exponent, modulus);

    result.to_signed_bytes_be()
}

// fn verify_pkcs1v15(pub_key: &PublicKey, hash: usize, hashed: &[u8], sig: &[u8]) -> Result<(), Box<dyn Error>> {
pub fn verify_pkcs1v15(pub_key: &PublicKey, hash: usize, hashed: &[u8], sig: &[u8]) -> bool {
    let (hash_len, prefix) = pkcs1v15_hash_info(hash, hashed.len()); // let (hash_len, prefix) = pkcs1v15_hash_info(hash, hashed.len())?;
    let t_len = &prefix.clone().unwrap().len() + hash_len;
    let k = pub_key.size();

    if k < t_len + 11 {
        return false; //return Err("verification error".into());
    }

    if k != sig.len() {
        return false; // return Err("verification error".into());
    }

    let em = encrypt(pub_key, sig); // let em = encrypt(pub_key, sig)?;

    let mut ok = em[0] == 0 && em[1] == 1;
    ok &= (&em[k - hash_len..k] == hashed);
    ok &= (&em[k - t_len..(k - hash_len)] == &prefix.unwrap());
    ok &= (em[k - t_len - 1] == 0);

    for i in 2..(k - t_len - 1) {
        ok &= (em[i] == 0xff);
    }

    if !ok {
        return false; //return Err("verification error".into());
    }

    true //Ok(())
}

fn pkcs1v15_hash_info(hash: usize, in_len: usize) -> (usize, Option<Vec<u8>>) { // fn pkcs1v15_hash_info(hash: CryptoHash, in_len: usize) -> Result<(usize, Option<Vec<u8>>), Box<dyn Error>> {
    // Специальный случай: хеш 0 используется для указания на то, что данные
    // подписаны напрямую.
    if hash == 0 { // if hash.size() == 0 {
        return (in_len, None); // return Ok((in_len, None));
    }

    //let hash_len = hash.size();
    if in_len != hash { // if in_len != hash_len {
        panic!("crypto/rsa: input must be hashed message");//return Err("crypto/rsa: input must be hashed message".into());
    }

    let prefix = get_hash_prefix(hash); // let prefix = get_hash_prefix(&hash)?;
    (hash, prefix) // Ok((hash_len, prefix))
}

// fn get_hash_prefix(hash: usize) -> Result<Vec<u8>, Box<dyn Error>> {
fn get_hash_prefix(hash: usize) -> Option<Vec<u8>> {
    match hash {
        224 => { // SHA224
            //
            Some(vec![
                0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04, 0x05, 0x00, 0x04, 0x1c,
            ])
        },
        256 => { // SHA256
            Some(vec![
                0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20,
            ])
        },
        384 => { // SHA384
            Some(vec![
                0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30,
            ])
        },
        512 => { // SHA512
            Some(vec![
                0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40,
            ])

        },
        _ => None, // Err("unsupported hash function".into()),
    }
}
