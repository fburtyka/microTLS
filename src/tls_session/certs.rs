mod rsa;
mod ecdsa;
mod ed25519;

///mod hkdf_sha256;

use crate::tls_session::hkdf_sha256;

//use core::slice::SlicePattern;
use std::net;
use std::ops::{AddAssign, Deref};
//use std::time::SystemTime;
use chrono::{DateTime, Utc, TimeZone, ParseError};
use std::ops::Neg;

use num_bigint::{BigInt, ToBigInt, Sign};
//use num_traits::One;
use std::iter::FromIterator;
use std::str::FromStr;

use std::collections::{hash_map, HashMap};
//use crate::tls_session::certs::PublicKey::{ECDSA_PUBLIC_KEY, ED25519_PUBLIC_KEY, X25519_PUBLIC_KEY};

// ASN.1 objects have metadata preceding them:
//   the tag: the type of the object
//   a flag denoting if this object is compound or not
//   the class type: the namespace of the tag
//   the length of the object, in bytes

// Here are some standard tags and classes

// ASN.1 tags represent the type of the following object.
const TagBoolean: u8         = 1;
const TagInteger: u8         = 2;
const TagBitString: u8       = 3;
const TagOctetString: u8     = 4;
const TagNull: u8            = 5;
const TagOID: u8             = 6;
const TagEnum: u8            = 10;
const TagUTF8String: u8      = 12;
const TagSequence: u8        = 16;
const TagSet: u8             = 17;
const TagNumericString: u8   = 18;
const TagPrintableString: u8 = 19;
const TagT61String: u8       = 20;
const TagIA5String: u8       = 22;
const TagUTCTime: u8         = 23;
const TagGeneralizedTime: u8 = 24;
const TagGeneralString: u8   = 27;
const TagBMPString: u8       = 30;

// ASN.1 class types represent the namespace of the tag.
const ClassUniversal: u16       = 0;
const ClassApplication: u16     = 1;
const ClassContextSpecific: u16 = 2;
const ClassPrivate: u16         = 3;

// NullRawValue is a [RawValue] with its Tag set to the ASN.1 NULL type tag (5).
//const NullRawValue: RawValue = RawValue{Tag: TagNull};

// NullBytes contains bytes representing the DER-encoded ASN.1 NULL type.
const NullBytes: [u8; 2] = [TagNull, 0];

#[derive(Debug, PartialEq)]
pub enum SignatureAlgorithm {
    UnknownSignatureAlgorithm = 0,
    MD2WithRSA = 1,   // Unsupported.
    MD5WithRSA = 2,   // Only supported for signing, not verification.
    SHA1WithRSA = 3,  // Only supported for signing, and verification of CRLs, CSRs, and OCSP responses.
    SHA256WithRSA = 4,
    SHA384WithRSA = 5,
    SHA512WithRSA = 6,
    DSAWithSHA1 = 7, // Unsupported.
    DSAWithSHA256 = 8, // Unsupported.
    ECDSAWithSHA1 = 9, // Only supported for signing, and verification of CRLs, CSRs, and OCSP responses.
    ECDSAWithSHA256 = 10,
    ECDSAWithSHA384 = 11,
    ECDSAWithSHA512 = 12,
    SHA256WithRSAPSS = 13,
    SHA384WithRSAPSS = 14,
    SHA512WithRSAPSS = 15,
    PureEd25519 = 16,
}
/*
const UnknownSignatureAlgorithm: u16 = 0;
const MD2WithRSA: u16 = 1;  // Unsupported.
const MD5WithRSA: u16 = 2;  // Only supported for signing, not verification.
const SHA1WithRSA: u16 = 3; // Only supported for signing, and verification of CRLs, CSRs, and OCSP responses.
const SHA256WithRSA: u16 = 4;
const SHA384WithRSA: u16 = 5;
const SHA512WithRSA: u16 = 6;
const DSAWithSHA1: u16 = 7;   // Unsupported.
const DSAWithSHA256: u16 = 8; // Unsupported.
const ECDSAWithSHA1: u16 = 9; // Only supported for signing, and verification of CRLs, CSRs, and OCSP responses.
const ECDSAWithSHA256: u16 = 10;
const ECDSAWithSHA384: u16 = 11;
const ECDSAWithSHA512: u16 = 12;
const SHA256WithRSAPSS: u16 = 13;
const SHA384WithRSAPSS: u16 = 14;
const SHA512WithRSAPSS: u16 = 15;
const PureEd25519: u16 = 16;*/

impl SignatureAlgorithm {
    fn is_rsa_pss(&self) -> bool {
        match self {
            SignatureAlgorithm::SHA256WithRSAPSS => true,
            SignatureAlgorithm::SHA384WithRSAPSS => true,
            SignatureAlgorithm::SHA512WithRSAPSS => true,
            _ => false,
        }
    }
}

pub const ROOT_CERT_FROM_ONLINE: [u8; 1382] = [48, 130, 5, 98, 48, 130, 4, 74, 160, 3, 2, 1, 2, 2, 16, 119, 189, 13, 108, 219, 54, 249, 26, 234, 33, 15, 196, 240,
        88, 211, 13, 48, 13, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 11, 5, 0, 48, 87, 49, 11, 48, 9, 6, 3, 85, 4, 6, 19, 2, 66, 69, 49, 25, 48, 23,
        6, 3, 85, 4, 10, 19, 16, 71, 108, 111, 98, 97, 108, 83, 105, 103, 110, 32, 110, 118, 45, 115, 97, 49, 16, 48, 14, 6, 3, 85, 4, 11, 19, 7,
        82, 111, 111, 116, 32, 67, 65, 49, 27, 48, 25, 6, 3, 85, 4, 3, 19, 18, 71, 108, 111, 98, 97, 108, 83, 105, 103, 110, 32, 82, 111, 111, 116,
        32, 67, 65, 48, 30, 23, 13, 50, 48, 48, 54, 49, 57, 48, 48, 48, 48, 52, 50, 90, 23, 13, 50, 56, 48, 49, 50, 56, 48, 48, 48, 48, 52, 50, 90,
        48, 71, 49, 11, 48, 9, 6, 3, 85, 4, 6, 19, 2, 85, 83, 49, 34, 48, 32, 6, 3, 85, 4, 10, 19, 25, 71, 111, 111, 103, 108, 101, 32, 84, 114,
        117, 115, 116, 32, 83, 101, 114, 118, 105, 99, 101, 115, 32, 76, 76, 67, 49, 20, 48, 18, 6, 3, 85, 4, 3, 19, 11, 71, 84, 83, 32, 82, 111,
        111, 116, 32, 82, 49, 48, 130, 2, 34, 48, 13, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 1, 5, 0, 3, 130, 2, 15, 0, 48, 130, 2, 10, 2, 130, 2,
        1, 0, 182, 17, 2, 139, 30, 227, 161, 119, 155, 59, 220, 191, 148, 62, 183, 149, 167, 64, 60, 161, 253, 130, 249, 125, 50, 6, 130, 113, 246,
        246, 140, 127, 251, 232, 219, 188, 106, 46, 151, 151, 163, 140, 75, 249, 43, 246, 177, 249, 206, 132, 29, 177, 249, 197, 151, 222, 239, 185,
        242, 163, 233, 188, 18, 137, 94, 167, 170, 82, 171, 248, 35, 39, 203, 164, 177, 156, 99, 219, 215, 153, 126, 240, 10, 94, 235, 104, 166, 244,
        198, 90, 71, 13, 77, 16, 51, 227, 78, 177, 19, 163, 200, 24, 108, 75, 236, 252, 9, 144, 223, 157, 100, 41, 37, 35, 7, 161, 180, 210, 61, 46,
        96, 224, 207, 210, 9, 135, 187, 205, 72, 240, 77, 194, 194, 122, 136, 138, 187, 186, 207, 89, 25, 214, 175, 143, 176, 7, 176, 158, 49, 241,
        130, 193, 192, 223, 46, 166, 109, 108, 25, 14, 181, 216, 126, 38, 26, 69, 3, 61, 176, 121, 164, 148, 40, 173, 15, 127, 38, 229, 168, 8, 254,
        150, 232, 60, 104, 148, 83, 238, 131, 58, 136, 43, 21, 150, 9, 178, 224, 122, 140, 46, 117, 214, 156, 235, 167, 86, 100, 143, 150, 79, 104,
        174, 61, 151, 194, 132, 143, 192, 188, 64, 192, 11, 92, 189, 246, 135, 179, 53, 108, 172, 24, 80, 127, 132, 224, 76, 205, 146, 211, 32, 233,
        51, 188, 82, 153, 175, 50, 181, 41, 179, 37, 42, 180, 72, 249, 114, 225, 202, 100, 247, 230, 130, 16, 141, 232, 157, 194, 138, 136, 250, 56,
        102, 138, 252, 99, 249, 1, 249, 120, 253, 123, 92, 119, 250, 118, 135, 250, 236, 223, 177, 14, 121, 149, 87, 180, 189, 38, 239, 214, 1, 209,
        235, 22, 10, 187, 142, 11, 181, 197, 197, 138, 85, 171, 211, 172, 234, 145, 75, 41, 204, 25, 164, 50, 37, 78, 42, 241, 101, 68, 208, 2, 206,
        170, 206, 73, 180, 234, 159, 124, 131, 176, 64, 123, 231, 67, 171, 167, 108, 163, 143, 125, 137, 129, 250, 76, 165, 255, 213, 142, 195, 206,
        75, 224, 181, 216, 179, 142, 69, 207, 118, 192, 237, 64, 43, 253, 83, 15, 176, 167, 213, 59, 13, 177, 138, 162, 3, 222, 49, 173, 204, 119,
        234, 111, 123, 62, 214, 223, 145, 34, 18, 230, 190, 250, 216, 50, 252, 16, 99, 20, 81, 114, 222, 93, 214, 22, 147, 189, 41, 104, 51, 239,
        58, 102, 236, 7, 138, 38, 223, 19, 215, 87, 101, 120, 39, 222, 94, 73, 20, 0, 162, 0, 127, 154, 168, 33, 182, 169, 177, 149, 176, 165, 185,
        13, 22, 17, 218, 199, 108, 72, 60, 64, 224, 126, 13, 90, 205, 86, 60, 209, 151, 5, 185, 203, 75, 237, 57, 75, 156, 196, 63, 210, 85, 19,
        110, 36, 176, 214, 113, 250, 244, 193, 186, 204, 237, 27, 245, 254, 129, 65, 216, 0, 152, 61, 58, 200, 174, 122, 152, 55, 24, 5, 149, 2,
        3, 1, 0, 1, 163, 130, 1, 56, 48, 130, 1, 52, 48, 14, 6, 3, 85, 29, 15, 1, 1, 255, 4, 4, 3, 2, 1, 134, 48, 15, 6, 3, 85, 29, 19, 1, 1, 255,
        4, 5, 48, 3, 1, 1, 255, 48, 29, 6, 3, 85, 29, 14, 4, 22, 4, 20, 228, 175, 43, 38, 113, 26, 43, 72, 39, 133, 47, 82, 102, 44, 239, 240, 137,
        19, 113, 62, 48, 31, 6, 3, 85, 29, 35, 4, 24, 48, 22, 128, 20, 96, 123, 102, 26, 69, 13, 151, 202, 137, 80, 47, 125, 4, 205, 52, 168, 255,
        252, 253, 75, 48, 96, 6, 8, 43, 6, 1, 5, 5, 7, 1, 1, 4, 84, 48, 82, 48, 37, 6, 8, 43, 6, 1, 5, 5, 7, 48, 1, 134, 25, 104, 116, 116, 112,
        58, 47, 47, 111, 99, 115, 112, 46, 112, 107, 105, 46, 103, 111, 111, 103, 47, 103, 115, 114, 49, 48, 41, 6, 8, 43, 6, 1, 5, 5, 7, 48, 2,
        134, 29, 104, 116, 116, 112, 58, 47, 47, 112, 107, 105, 46, 103, 111, 111, 103, 47, 103, 115, 114, 49, 47, 103, 115, 114, 49, 46, 99, 114,
        116, 48, 50, 6, 3, 85, 29, 31, 4, 43, 48, 41, 48, 39, 160, 37, 160, 35, 134, 33, 104, 116, 116, 112, 58, 47, 47, 99, 114, 108, 46, 112,
        107, 105, 46, 103, 111, 111, 103, 47, 103, 115, 114, 49, 47, 103, 115, 114, 49, 46, 99, 114, 108, 48, 59, 6, 3, 85, 29, 32, 4, 52, 48, 50,
        48, 8, 6, 6, 103, 129, 12, 1, 2, 1, 48, 8, 6, 6, 103, 129, 12, 1, 2, 2, 48, 13, 6, 11, 43, 6, 1, 4, 1, 214, 121, 2, 5, 3, 2, 48, 13, 6, 11,
        43, 6, 1, 4, 1, 214, 121, 2, 5, 3, 3, 48, 13, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 11, 5, 0, 3, 130, 1, 1, 0, 52, 164, 30, 177, 40, 163,
        208, 180, 118, 23, 166, 49, 122, 33, 233, 209, 82, 62, 200, 219, 116, 22, 65, 136, 184, 61, 53, 29, 237, 228, 255, 147, 225, 92, 95, 171,
        187, 234, 124, 207, 219, 228, 13, 209, 139, 87, 242, 38, 111, 91, 190, 23, 70, 104, 148, 55, 111, 107, 122, 200, 192, 24, 55, 250, 37, 81,
        172, 236, 104, 191, 178, 200, 73, 253, 90, 154, 202, 1, 35, 172, 132, 128, 43, 2, 140, 153, 151, 235, 73, 106, 140, 117, 215, 199, 222,
        178, 201, 151, 159, 88, 72, 87, 14, 53, 161, 228, 26, 214, 253, 111, 131, 129, 111, 239, 140, 207, 151, 175, 192, 133, 42, 240, 245, 78,
        105, 9, 145, 45, 225, 104, 184, 193, 43, 115, 233, 212, 217, 252, 34, 192, 55, 31, 11, 102, 29, 73, 237, 2, 85, 143, 103, 225, 50, 215,
        211, 38, 191, 112, 227, 61, 244, 103, 109, 61, 124, 229, 52, 136, 227, 50, 250, 167, 110, 6, 106, 111, 189, 139, 145, 238, 22, 75, 232,
        59, 169, 179, 55, 231, 195, 68, 164, 126, 216, 108, 215, 199, 70, 245, 146, 155, 231, 213, 33, 190, 102, 146, 25, 148, 85, 108, 212, 41,
        178, 13, 193, 102, 91, 226, 119, 73, 72, 40, 237, 157, 215, 26, 51, 114, 83, 179, 130, 53, 207, 98, 139, 201, 36, 139, 165, 183, 57, 12,
        187, 126, 42, 65, 191, 82, 207, 252, 162, 150, 182, 194, 130, 63];


const OID_SIGNATURE_MD2_WITH_RSA: [i32; 7]      = [1, 2, 840, 113549, 1, 1, 2];
const OID_SIGNATURE_MD5_WITH_RSA: [i32; 7]      = [1, 2, 840, 113549, 1, 1, 4];
const OID_SIGNATURE_SHA1_WITH_RSA: [i32; 7]     = [1, 2, 840, 113549, 1, 1, 5];
const OID_SIGNATURE_SHA256_WITH_RSA: [i32; 7]   = [1, 2, 840, 113549, 1, 1, 11];
const OID_SIGNATURE_SHA384_WITH_RSA: [i32; 7]   = [1, 2, 840, 113549, 1, 1, 12];
const OID_SIGNATURE_SHA512_WITH_RSA: [i32; 7]   = [1, 2, 840, 113549, 1, 1, 13];
const OID_SIGNATURE_RSA_PSS: [i32; 7]          = [1, 2, 840, 113549, 1, 1, 10];
const OID_SIGNATURE_DSA_WITH_SHA1: [i32; 6]     = [1, 2, 840, 10040, 4, 3];
const OID_SIGNATURE_DSA_WITH_SHA256: [i32; 9]   = [2, 16, 840, 1, 101, 3, 4, 3, 2];
const OID_SIGNATURE_ECDSA_WITH_SHA1: [i32; 6]   = [1, 2, 840, 10045, 4, 1];
const OID_SIGNATURE_ECDSA_WITH_SHA256: [i32; 7] = [1, 2, 840, 10045, 4, 3, 2];
const OID_SIGNATURE_ECDSA_WITH_SHA384: [i32; 7] = [1, 2, 840, 10045, 4, 3, 3];
const OID_SIGNATURE_ECDSA_WITH_SHA512: [i32; 7] = [1, 2, 840, 10045, 4, 3, 4];
const OID_SIGNATURE_ED25519: [i32; 4] = [1, 3, 101, 112];



const OID_SHA256: [i32; 9] = [2, 16, 840, 1, 101, 3, 4, 2, 1];
const OID_SHA384: [i32; 9] = [2, 16, 840, 1, 101, 3, 4, 2, 2];
const OID_SHA512: [i32; 9] = [2, 16, 840, 1, 101, 3, 4, 2, 3];

const OID_MGF1: [i32; 7] = [1, 2, 840, 113549, 1, 1, 8];

// oidISOSignatureSHA1WithRSA means the same as oidSignatureSHA1WithRSA
// but it's specified by ISO. Microsoft's makecert.exe has been known
// to produce certificates with this OID.
const oidISOSignatureSHA1WithRSA: [i32; 6] = [1, 3, 14, 3, 2, 29];


const UnknownPublicKeyAlgorithm: u16 = 0;
const RSA: u16 = 1;
const DSA: u16 = 2; // Only supported for parsing.
const ECDSA: u16 = 3;
const Ed25519: u16 = 4;

#[derive(Debug, PartialEq)]
pub enum PublicKeyAlgorithm {
    UnknownPublicKeyAlgorithm = 0,
    RSA = 1,
    DSA = 2,
    ECDSA = 3,
    Ed25519 = 4,
}

impl PublicKeyAlgorithm {
    pub fn to_string(&self) -> String {
        match self {
            PublicKeyAlgorithm::UnknownPublicKeyAlgorithm => "UnknownPublicKeyAlgorithm".to_string(),
            PublicKeyAlgorithm::RSA => "RSA".to_string(),
            PublicKeyAlgorithm::DSA => "DSA".to_string(),
            PublicKeyAlgorithm::ECDSA => "ECDSA".to_string(),
            PublicKeyAlgorithm::Ed25519 => "Ed25519".to_string(),
        }
    }
}

#[derive(Debug)]
struct AlgorithmDetails {
    algo: SignatureAlgorithm,
    name: String,
    oid: Vec<i32>, //ObjectIdentifier,
    pub_key_algo: PublicKeyAlgorithm,
    hash: Option<String>, // Можно использовать String для хеш-алгоритма
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct KeyUsage(i32);

impl KeyUsage {
    pub const DIGITAL_SIGNATURE: KeyUsage = KeyUsage(1 << 0);
    pub const CONTENT_COMMITMENT: KeyUsage = KeyUsage(1 << 1);
    pub const KEY_ENCIPHERMENT: KeyUsage = KeyUsage(1 << 2);
    pub const DATA_ENCIPHERMENT: KeyUsage = KeyUsage(1 << 3);
    pub const KEY_AGREEMENT: KeyUsage = KeyUsage(1 << 4);
    pub const CERT_SIGN: KeyUsage = KeyUsage(1 << 5);
    pub const CRL_SIGN: KeyUsage = KeyUsage(1 << 6);
    pub const ENCIPHER_ONLY: KeyUsage = KeyUsage(1 << 7);
    pub const DECIPHER_ONLY: KeyUsage = KeyUsage(1 << 8);
}

#[derive(Debug, Clone, Copy)]
pub struct ExtKeyUsage(i32);

impl ExtKeyUsage {
    pub const ANY: ExtKeyUsage = ExtKeyUsage(0);
    pub const SERVER_AUTH: ExtKeyUsage = ExtKeyUsage(1);
    pub const CLIENT_AUTH: ExtKeyUsage = ExtKeyUsage(2);
    pub const CODE_SIGNING: ExtKeyUsage = ExtKeyUsage(3);
    pub const EMAIL_PROTECTION: ExtKeyUsage = ExtKeyUsage(4);
    pub const IPSEC_END_SYSTEM: ExtKeyUsage = ExtKeyUsage(5);
    pub const IPSEC_TUNNEL: ExtKeyUsage = ExtKeyUsage(6);
    pub const IPSEC_USER: ExtKeyUsage = ExtKeyUsage(7);
    pub const TIME_STAMPING: ExtKeyUsage = ExtKeyUsage(8);
    pub const OCSP_SIGNING: ExtKeyUsage = ExtKeyUsage(9);
    pub const MICROSOFT_SERVER_GATED_CRYPTO: ExtKeyUsage = ExtKeyUsage(10);
    pub const NETSCAPE_SERVER_GATED_CRYPTO: ExtKeyUsage = ExtKeyUsage(11);
    pub const MICROSOFT_COMMERCIAL_CODE_SIGNING: ExtKeyUsage = ExtKeyUsage(12);
    pub const MICROSOFT_KERNEL_CODE_SIGNING: ExtKeyUsage = ExtKeyUsage(13);
}


#[derive(Debug)]
pub struct PssParameters {
    // Поля не являются обязательными, так как значения по умолчанию
    // указывают на SHA-1 (который больше не подходит для использования в подписях).
    pub hash: AlgorithmIdentifier,
    pub mgf: AlgorithmIdentifier,
    pub salt_length: i32,
    pub trailer_field: Option<i32>, // Опциональное поле с значением по умолчанию 1
}



// Tag represents an ASN.1 identifier octet, consisting of a tag number
// (indicating a type) and class (such as context-specific or constructed).
//
// Methods in the cryptobyte package only support the low-tag-number form, i.e.
// a single identifier octet with bits 7-8 encoding the class and bits 1-6
// encoding the tag number.
//#[derive(Clone, Copy, Debug)]
//pub struct Tag(u8);

const CLASS_CONSTRUCTED: u8 = 0x20;
const CLASS_CONTEXT_SPECIFIC: u8 = 0x80;

// Методы для Tag
//impl Tag {

    //pub fn constructed(self) -> Tag {
        //Tag(self.0 | CLASS_CONSTRUCTED)
    //}

    // Установка бита контекстного специфического класса
    //pub fn context_specific(self) -> Tag {
        //Tag(self.0 | CLASS_CONTEXT_SPECIFIC)
    //}
//}

pub fn context_specific(tag: u8) -> u8 {
    tag | CLASS_CONTEXT_SPECIFIC
}
pub fn constructed(tag: u8) -> u8 {
    tag | CLASS_CONSTRUCTED
}

// Стандартные комбинации тегов и классов
//pub const BOOLEAN: Tag = Tag(1);
//pub const INTEGER: Tag = Tag(2);
//pub const BIT_STRING: Tag = Tag(3);
//pub const OCTET_STRING: Tag = Tag(4);
//pub const NULL: Tag = Tag(5);
//pub const OBJECT_IDENTIFIER: Tag = Tag(6);
//pub const ENUM: Tag = Tag(10);
//pub const UTF8_STRING: Tag = Tag(12);
//pub const SEQUENCE: Tag = Tag(16 | CLASS_CONSTRUCTED);
//pub const SET: Tag = Tag(17 | CLASS_CONSTRUCTED);
//pub const PRINTABLE_STRING: Tag = Tag(19);
//pub const T61_STRING: Tag = Tag(20);
//pub const IA5_STRING: Tag = Tag(22);
//pub const UTC_TIME: Tag = Tag(23);
//pub const GENERALIZED_TIME: Tag = Tag(24);
//pub const GENERAL_STRING: Tag = Tag(27);

pub const BOOLEAN: u8 = 1u8;
pub const INTEGER: u8 = 2u8;
pub const BIT_STRING: u8 = 3u8;
pub const OCTET_STRING: u8 = 4u8;
pub const NULL: u8 = 5u8;
pub const OBJECT_IDENTIFIER: u8 = 6u8;
pub const ENUM: u8 = 10u8;
pub const UTF8_STRING: u8 = 12u8;
pub const SEQUENCE: u8 = 16u8 | CLASS_CONSTRUCTED;
pub const SET: u8 = 17u8 | CLASS_CONSTRUCTED;
pub const NUMERIC_STRING: u8 = 18u8;
pub const PRINTABLE_STRING: u8 = 19u8;
pub const T61_STRING: u8 = 20u8;
pub const IA5_STRING: u8 = 22u8;
pub const UTC_TIME: u8 = 23u8;
pub const GENERALIZED_TIME: u8 = 24u8;
pub const GENERAL_STRING: u8 = 27u8;
pub const BMP_STRING: u8 = 30u8;

struct BitString {
    pub bytes: Vec<u8>,
    pub bit_length: usize,
}

impl BitString {

    // at returns the bit at the given index. If the index is out of range it
    // returns 0.
    pub fn at(&self, i: usize) -> u8 {
        if i >= self.bit_length {
            return 0u8;
        }
        let x = i / 8;
        let y = 7 - (i%8) as u8;
        (self.bytes[x]>>y) & 1
    }

    // right_align returns a slice where the padding bits are at the beginning. The
    // slice may share memory with the BitString.
    pub fn right_align(&self) -> Vec<u8> {
        let shift = (8 - (self.bit_length % 8)) as u8;
        if shift == 8 || self.bytes.is_empty() {
            return self.bytes.clone();
        }

        let mut a = vec![0u8; self.bytes.len()];
        a[0] = self.bytes[0] >> shift;
        for i in 1..self.bytes.len() {
            a[i] = self.bytes[i-1] << (8 - shift);
            a[i] |= self.bytes[i] >> shift;
        }
        return a;
    }
}

// Предполагается, что String - это структура, которая обрабатывает данные ASN.1
#[derive(Debug, Clone)]
pub struct ASN1String(Vec<u8>); // Используется Vec<u8> для представления строки

impl ASN1String {

    pub fn read_asn1_bitstring(&mut self, out: &mut BitString) -> bool {
        let mut bytes = ASN1String{ 0: Vec::new()};
        if !self.read_asn1(&mut bytes, BIT_STRING) || bytes.0.is_empty() || bytes.0.len()*8/8 != bytes.0.len() {
            return false;
        }

        let padding_bits = bytes.0[0];
        bytes.0 = bytes.0[1..].to_vec();

        if padding_bits > 7 ||
		bytes.0.is_empty() && padding_bits != 0 ||
		bytes.0.len() > 0 && (bytes.0[bytes.0.len()-1] & (((1<<padding_bits) as i8 - 1i8) != 0i8) as u8) != 0u8 {
            return false;
        }
        out.bit_length = (bytes.0.len()*8) as usize - (padding_bits as usize);
        out.bytes = bytes.0;
        return true
    }


    pub fn read_asn1(&mut self, out: &mut ASN1String, tag: u8) -> bool {
        let mut t = 0u8;
        if !self.read_any_asn1(out, &mut t) || t != tag {
            return false;
        }
        true
    }

    // Чтение ASN.1 элемента
    // ReadASN1Element reads the contents of a DER-encoded ASN.1 element (including
    // tag and length bytes) into out, and advances. The element must match the
    // given tag. It reports whether the read was successful.
    //
    // Tags greater than 30 are not supported (i.e. low-tag-number format only).
    pub fn read_asn1_element(&mut self, out: &mut ASN1String, tag: u8) -> bool {
        let mut t = 0u8;

        if !self.read_any_asn1_element(out, &mut t) || t != tag {
            return false;
        }
        true
    }

    // Чтение любого ASN.1
    pub fn read_any_asn1(&mut self, out: &mut ASN1String, out_tag: &mut u8) -> bool {
        self.read_asn1_impl(out, out_tag, true)
    }

    // ReadAnyASN1Element reads the contents of a DER-encoded ASN.1 element
    // (including tag and length bytes) into out, sets outTag to is tag, and
    // advances. It reports whether the read was successful.
    //
    // Tags greater than 30 are not supported (i.e. low-tag-number format only).
    pub fn read_any_asn1_element(&mut self, out: &mut ASN1String, out_tag: &mut u8) -> bool {
        self.read_asn1_impl(out, out_tag, false)
    }

    // Проверка тега ASN.1
    pub fn peek_asn1_tag(&self, tag: u8) -> bool {
        self.0.is_empty().then(|| false).unwrap_or(self.0[0] == tag)
    }

    // Пропуск ASN.1
    pub fn skip_asn1(&mut self, tag: u8) -> bool {
        let mut unused = ASN1String(vec![]);
        self.read_asn1(&mut unused, tag)
    }

    // Чтение необязательного ASN.1
    pub fn read_optional_asn1(&mut self, out: &mut ASN1String, out_present: &mut bool, tag: u8) -> bool {
        let present = self.peek_asn1_tag(tag);
        //if let Some(ref mut p) = out_present {
            // *p = present;
        //}
        *out_present = present;
        if present && !self.read_asn1(out, tag) {
            return false;
        }
        true
    }

    // Пропуск необязательного ASN.1
    pub fn skip_optional_asn1(&mut self, tag: u8) -> bool {
        if !self.peek_asn1_tag(tag) {
            return true;
        }
        let mut unused = ASN1String(vec![]);
        self.read_asn1(&mut unused, tag)
    }

    // Чтение необязательного ASN.1 целого числа
    // pub fn read_optional_asn1_integer(&mut self, out: &mut dyn std::any::Any, tag: Tag, default_value: &dyn std::any::Any) -> bool {
    pub fn read_optional_asn1_integer(&mut self, out: &mut i64, tag: u8, default_value: i64) -> bool {
        let mut present = false;
        let mut i = ASN1String(vec![]);

        if !self.read_optional_asn1(&mut i, &mut present, tag) {
            return false;
        }

        if !present {
            //match out.downcast_mut::<i32>() {
                //Some(o) => *o = *default_value.downcast_ref::<i32>().unwrap(),
                //None => panic!("invalid type"),
            //}
            *out = default_value;
            return true;
        }

        if !i.read_asn1_i64(out) || !i.0.is_empty() {
            return false;
        }

        true
    }

    // read_asn1_boolean decodes an ASN.1 BOOLEAN and converts it to a boolean
    // representation into out and advances. It reports whether the read
    // was successful.
    fn read_asn1_boolean(&mut self, out: &mut bool) -> bool {
        let mut bytes = ASN1String{0: Vec::new()};
        if !self.read_asn1(&mut bytes, BOOLEAN) || bytes.0.len() != 1 {
            return false;
        }
        match bytes.0[0] {
            0 => *out = false,
            0xff => *out = true,
            _ => return false,
        }
        return true;
    }

    pub fn read_asn1_i64(&mut self, out: &mut i64) -> bool {
        let mut bytes = ASN1String{ 0: Vec::new()};
        // if !self.read_asn1(&mut bytes, INTEGER) || !check_asn1_integer(bytes) || !asn1_signed(out, &bytes) {
        if !self.read_asn1(&mut bytes, INTEGER) || !check_asn1_integer(&bytes.0) || !asn1_signed(out, &bytes.0) {
            return false;
        }
        return true;
    }




    // Чтение ASN.1 INTEGER в out
    //pub fn read_asn1_integer(&mut self, out: &mut dyn std::any::Any) -> bool { // pub fn read_asn1_integer(&mut self, out: &mut dyn std::any::Any) -> bool {
        // Пробуем получить указатель на тип числа
        //if let Some(out_int) = out.downcast_mut::<i64>() {
            //let mut i: i64 = 0;
            //if !self.read_asn1_int64(&mut i) {
                //return false;
            //}
            // *out_int = i; // Устанавливаем значение
            //return true;
        //} else if let Some(out_uint) = out.downcast_mut::<u64>() {
            //let mut u: u64 = 0;
            //if !self.read_asn1_uint64(&mut u) {
                //return false;
            //}
            // *out_uint = u; // Устанавливаем значение
            //return true;
        //} else if let Some(out_big) = out.downcast_mut::<BigInt>() {
            //return self.read_asn1_big_int(out_big);
        //} else if let Some(out_bytes) = out.downcast_mut::<Vec<u8>>() {
            //return self.read_asn1_bytes(out_bytes);
        //}

        //panic!("out does not point to an integer type");

    //}


    pub fn read_asn1_int64(&mut self, out: &mut i64) -> bool {
        let mut bytes = ASN1String{ 0: Vec::new()}; // Заполнение bytes должно происходить здесь
        if !self.read_asn1(&mut bytes, INTEGER) || !check_asn1_integer(&bytes.0) || !asn1_signed(out, &bytes.0) {
            return false;
        }
        true
    }

    pub fn read_asn1_uint64(&mut self, out: &mut u64) -> bool {
        let mut bytes = ASN1String{ 0: Vec::new()}; // Заполнение bytes должно происходить здесь
        if !self.read_asn1(&mut bytes, INTEGER) || !check_asn1_integer(&bytes.0) || !asn1_unsigned(out, &bytes.0) {
            return false;
        }
        true
    }

    //pub fn read_asn1_big_int(&mut self, out: &mut BigInt) -> bool {
        //let mut bytes = ASN1String{ 0: Vec::new()}; // Предполагается, что будет обработка, чтобы заполнить bytes
        //if !self.read_asn1(&mut bytes, INTEGER) || !check_asn1_integer(&bytes.0) {
            //return false;
        //}

        //if bytes.0[0] & 0x80 == 0x80 {
            // Отрицательное число.
            //let mut neg = bytes.0.iter().map(|b| !b).collect::<Vec<u8>>();
            //*out = BigInt::from_bytes_be(Sign::Plus,&neg); //out.set_bytes(&neg);
            //out.add_assign(&BigInt::from(1));
            //out.neg(); // out.negate();
        //} else {
            //*out = BigInt::from_bytes_be(Sign::Plus,&bytes.0);//out.set_bytes(&bytes);
        //}
        //true
    //}

    pub fn read_asn1_big_int(&mut self) -> Option<BigInt> {
        let mut bytes = ASN1String{ 0: Vec::new()}; // Предполагается, что будет обработка, чтобы заполнить bytes
        if !self.read_asn1(&mut bytes, INTEGER) || !check_asn1_integer(&bytes.0) {
            return None;
        }

        let big_one = BigInt::from(1);//BigInt::one();

        if bytes.0[0] & 0x80 == 0x80 {
            // Отрицательное число
            let neg: Vec<u8> = bytes.0.iter().map(|&b| !b).collect();
            let mut out = BigInt::from_signed_bytes_be(&neg); // let mut out = BigInt::from_bytes_neg(&BigEndian, &neg);
            out += &big_one;
            Some(-out)
        } else {
            Some(BigInt::from_signed_bytes_be(&bytes.0)) // Some(BigInt::from_bytes_positive(&BigEndian, &bytes))
        }
    }

    pub fn read_asn1_object_identifier(&mut self, out: &mut Vec<i32>) -> bool {
        let mut bytes = ASN1String{ 0: Vec::new() }; // Инициализация вектора для хранения байтов
        if !self.read_asn1(&mut bytes, OBJECT_IDENTIFIER) || bytes.0.is_empty() {
            return false;
        }

        // В худшем случае, мы получаем два элемента из первого байта (который кодируется иначе),
        // а затем каждый varint — это один байт.
        let mut components = vec![0; bytes.0.len() + 1];

        // Первый varint - это 40*value1 + value2:
        // value1 может принимать значения 0, 1 и 2.
        let mut v: i32 = 0;
        if !bytes.read_base128_int(&mut v) {
            return false;
        }
        if v < 80 {
            components[0] = v / 40;
            components[1] = v % 40;
        } else {
            components[0] = 2;
            components[1] = v - 80;
        }

        let mut i = 2;
        while !bytes.0.is_empty() {
            if !bytes.read_base128_int(&mut v) {
                return false;
            }
            components[i] = v;
            i += 1;
        }
        *out = components[..i].to_vec();
        true
    }

    pub fn read_asn1_bytes(&mut self, out: &mut Vec<u8>) -> bool {
        let mut bytes = ASN1String{ 0: Vec::new()};  // Заполнение bytes должно происходить здесь
        if !self.read_asn1(&mut bytes, INTEGER) || !check_asn1_integer(&bytes.0) {
            return false;
        }
        if bytes.0[0] & 0x80 == 0x80 {
            return false;
        }
        while bytes.0.len() > 1 && bytes.0[0] == 0 {
            bytes.0.remove(0);
        }
        *out = bytes.0;
        true
    }

    pub fn read_base128_int(&mut self, out: &mut i32) -> bool {
        let mut ret = 0;
        for i in 0.. {
            if self.0.len() == 0 {
                return false; // Обработка конца данных
            }
            if i == 5 {
                return false; // Слишком много байтов
            }
            // Избежание переполнения int на 32-битной платформе
            if ret >= 1 << (31 - 7) {
                return false;
            }
            ret <<= 7;
            let b: u8 = self.read(1).unwrap()[0]; // Чтение одного байта

            // ITU-T X.690, секция 8.19.2:
            // Подидентификатор должен быть закодирован в минимально возможном количестве октетов,
            // то есть ведущий октет подидентификатора не должен иметь значение 0x80.
            if i == 0 && b == 0x80 {
                return false;
            }

            ret |= (b & 0x7f) as i32;
            if b & 0x80 == 0 {
                *out = ret;
                return true;
            }
        }
        false // усеченные данные
    }

    pub fn read_asn1_impl(&mut self, out: &mut ASN1String, out_tag: &mut u8, skip_header: bool) -> bool {
        if self.0.len() < 2 {
            return false;
        }

        let tag = self.0[0];
        let len_byte = self.0[1];

        if tag & 0x1f == 0x1f {
            // ITU-T X.690 section 8.1.2
            // Тег с частью 0x1f указывает на идентификатор с высоким номером тега.
            return false;
        }

        //if let Some(out_t) = out_tag {
            // *out_t = Tag(tag);
        //}
        *out_tag = tag;

        // ITU-T X.690 section 8.1.3
        let (length, header_len) = if len_byte & 0x80 == 0 {
            // Короткая длина (section 8.1.3.4), закодированная в битах 1-7.
            //println!("read_asn1_impl short len ");
            (u32::from(len_byte) + 2, 2)
        } else {
            // Длинная длина (section 8.1.3.5).
            let len_len = len_byte & 0x7f;

            if len_len == 0 || len_len > 4 || self.0.len() < (2 + len_len as usize) {
                //println!("read_asn1_impl long len false");
                return false;
            }

            let mut len_bytes = ASN1String(self.0[2..2 + len_len as usize].to_vec());
            let mut len32 = 0u32;
            //println!("read_asn1_impl len_bytes before is : {:?}", &len_bytes);
            if !len_bytes.read_unsigned(&mut len32, len_len as usize) {
                return false;
            }
            //println!("read_asn1_impl len_bytes after is : {:?}", &len_bytes);
            //println!("read_asn1_impl len32 is : {:?}", &len32);

            // ITU-T X.690 section 10.1 (DER length forms) требует кодирования длины
            // с минимальным числом октетов.
            if len32 < 128 {
                return false; // Длина должна была использовать короткое кодирование.
            }
            if (len32 >> ((len_len - 1) * 8)) == 0 {
                return false; // Ведущий октет равен 0.
            }

            let header_len = 2 + len_len as u32;
            if header_len + len32 < len32 {
                return false; // Переполнение.
            }
            (header_len + len32, header_len)
        };
        //println!("read_asn1_impl length is : {:?}", &length);
        //println!("read_asn1_impl header_len is : {:?}", &header_len);

        //println!("self.0 before !self.read_bytes(out, length as usize) is : {:?}", &self.0);
        if length as usize > self.0.len() || !self.read_bytes(out, length as usize) {
            return false;
        }
        //println!("read_asn1_impl out is : {:?}", &out);
        if skip_header && !out.skip(header_len as usize) {
            panic!("cryptobyte: internal error");
        }
        //println!("out (not panic) is : {:?}", &out);
        //println!("self.0 (not panic) is : {:?}", &self.0);

        true
    }

    // fn read_asn1_utc_time(&mut self) -> Result<DateTime<Utc>, String> {
    fn read_asn1_utc_time(&mut self) -> Option<DateTime<Utc>> {
        let mut bytes = ASN1String{ 0: Vec::new()};
        if !self.read_asn1(&mut bytes, TagUTCTime) {
            return None;//return Err("Malformed UTCTime".to_string());
        }

        let t = String::from_utf8_lossy(&bytes.0).into_owned();
        let format_str = "%y%m%d%H%M%SZ"; // Стандартный формат UTCTime
        match Utc.datetime_from_str(&t, format_str) {
            Ok(res) => {
                // Применение дополнительной логики для 2050 года
                //if res.year() >= 2050 {
                    //let res = res - chrono::Duration::days(36525); // -100 лет
                    //Ok(res)
                //} else {
                    //Ok(res)
                //}
                Some(res)
            }
            Err(_) => None,//Err("Failed to parse UTCTime".to_string()),
        }
    }

    // fn read_asn1_generalized_time(&mut self) -> Result<DateTime<Utc>, String> {
    fn read_asn1_generalized_time(&mut self) -> Option<DateTime<Utc>> {
        let mut bytes = ASN1String{ 0: Vec::new()};
        if !self.read_asn1(&mut bytes, TagGeneralizedTime) {
            return None;//Err("Malformed GeneralizedTime".to_string());
        }

        let t = String::from_utf8_lossy(&bytes.0).into_owned();
        let format_str = "%Y%m%d%H%M%S%.fZ"; // Стандартный формат GeneralizedTime
        match Utc.datetime_from_str(&t, format_str) {
            Ok(res) => Some(res),//Ok(res),
            Err(_) => None,//Err("Failed to parse GeneralizedTime".to_string()),
        }
    }


    // Реализация чтения беззнакового целого числа из ASN.1
    // Для упрощения реализации функции, предполагается,
    // что строка достаточной длины и возвращает true на успех.
    pub fn read_unsigned(&mut self, out: &mut u32, length: usize) -> bool {
        let v = self.read(length);
        if v.is_none() {
            return false;
        }

        let v = v.unwrap();
        let mut result: u32 = 0;

        for byte in v {
            result <<= 8;
            result |= byte as u32;
        }

        *out = result;
        true
    }

    // Прочитать n байтов, продвигая строку
    fn read(&mut self, n: usize) -> Option<Vec<u8>> {
        if self.0.len() < n || n == 0 {
            return None;
        }

        let v = self.0[..n].to_vec(); // Получаем срез и копируем его
        self.0.drain(..n); // Удаляем прочитанные байты из внутреннего вектора
        Some(v)
    }

    // Реализация чтения байтов из ASN.1
    // По аналогии с другим кодом, должна быть реализована.
    pub fn read_bytes(&mut self, out: &mut ASN1String, length: usize) -> bool {
        if let Some(v) = self.read(length) {
            *out = ASN1String{0:v}; // Копируем прочитанные байты в out
            true
        } else {
            false
        }
    }

    // Skip advances the String by n byte and reports whether it was successful.
    fn skip(&mut self, length: usize) -> bool {
        // Реализация пропуска определенного количества байтов
        //if length <= self.0.len() {
            //self.0.drain(..length);
            //true
        //} else {
            //false
        //}
        match self.read(length){
            Some(res) => true,
            None => false
        }
        // return s.read(n) != nil
    }

}

pub fn asn1_signed(out: &mut i64, n: &[u8]) -> bool {
    let length = n.len();
    if length > 8 {
        return false;
    }
    for &byte in n {
        *out <<= 8;
        *out |= byte as i64;
    }
    // Сдвиг для расширения знака результата.
    *out <<= 64 - (length as u8 * 8);
    *out >>= 64 - (length as u8 * 8);
    true
}

pub fn asn1_unsigned(out: &mut u64, n: &[u8]) -> bool {
    let length = n.len();
    if length > 9 || (length == 9 && n[0] != 0) {
        // Слишком велико для uint64.
        return false;
    }
    if n[0] & 0x80 != 0 {
        // Отрицательное число.
        return false;
    }
    for &byte in n {
        *out <<= 8;
        *out |= byte as u64;
    }
    true
}

// Проверка на корректность ASN.1 INTEGER
pub fn check_asn1_integer(bytes: &[u8]) -> bool {
    if bytes.is_empty() {
        // INTEGER кодируется как минимум одним октетом
        return false;
    }
    if bytes.len() == 1 {
        return true;
    }
    if (bytes[0] == 0 && (bytes[1] & 0x80) == 0) || (bytes[0] == 0xff && (bytes[1] & 0x80) == 0x80) {
        // Значение не минимально закодировано
        return false;
    }
    return true;
}

// Представляет набор AttributeTypeAndValue
//#[derive(Debug, Clone)]
//pub struct AttributeTypeAndValueSET {
    //pub rtype: ObjectIdentifier,
    //pub value: Vec<Vec<AttributeTypeAndValue>>, // Вектор векторов
//}

// Представляет расширение
#[derive(Debug, Clone)]
pub struct Extension {
    pub id: Vec<i32>, // //pub id: ObjectIdentifier,
    pub critical: Option<bool>, // Используем Option для обозначения опционального поля
    pub value: Vec<u8>,
}

// Представляет отличительное имя X.509
#[derive(Debug, Clone)]
pub struct Name {
    pub country: Vec<String>,
    pub organization: Vec<String>,
    pub organizational_unit: Vec<String>,
    pub locality: Vec<String>,
    pub province: Vec<String>,
    pub street_address: Vec<String>,
    pub postal_code: Vec<String>,
    pub serial_number: String,
    pub common_name: String,
    pub names: Vec<AttributeTypeAndValue>, // Все разобранные атрибуты
    pub extra_names: Vec<AttributeTypeAndValue>, // Атрибуты, копируемые в любые сериализованные имена
}

impl Name {
    pub fn default() -> Self {
        Name {
            country: Vec::new(),
            organization: Vec::new(),
            organizational_unit: Vec::new(),
            locality: Vec::new(),
            province: Vec::new(),
            street_address: Vec::new(),
            postal_code: Vec::new(),
            serial_number: String::new(),
            common_name: String::new(),
            names: Vec::new(),
            extra_names: Vec::new(),
        }
    }

    // FillFromRDNSequence populates Name from the provided [RDNSequence].
    // Multi-entry RDNs are flattened, all entries are added to the
    // relevant Name's fields, and the grouping is not preserved.
    pub fn fill_from_rdn_sequence(&mut self, rdns: &Vec<Vec<AttributeTypeAndValue>>) {
        for rdn in rdns {
            if rdn.is_empty() {
                continue;
            }

            for atv in rdn {
                self.names.push(atv.clone()); // Сохраняем атрибут

                // Проверяем значение
                let value = &atv.value;

                let t = &atv.atype;
                if t.len() == 4 && t[0] == 2 && t[1] == 5 && t[2] == 4 {
                    match t[3] {
                        3 => self.common_name = value.clone(),
                        5 => self.serial_number = value.clone(),
                        6 => self.country.push(value.clone()),
                        7 => self.locality.push(value.clone()),
                        8 => self.province.push(value.clone()),
                        9 => self.street_address.push(value.clone()),
                        10 => self.organization.push(value.clone()),
                        11 => self.organizational_unit.push(value.clone()),
                        17 => self.postal_code.push(value.clone()),
                        _ => {}
                    }
                }

            }
        }
    }
}

#[derive(Debug)]
struct Certificate {
    raw: Vec<u8>,                             // Complete ASN.1 DER content
    raw_tbs_certificate: Vec<u8>,             // Certificate part of raw ASN.1 DER content
    raw_subject_public_key_info: Vec<u8>,    // DER encoded SubjectPublicKeyInfo
    raw_subject: Vec<u8>,                     // DER encoded Subject
    raw_issuer: Vec<u8>,                      // DER encoded Issuer

    signature: Vec<u8>,
    signature_algorithm: SignatureAlgorithm,
    public_key_algorithm: PublicKeyAlgorithm,
    public_key: PublicKey,    // Using trait object for dynamic dispatch

    version: i64,
    serial_number: BigInt,     // serial_number: Option<BigInt>,          // Type for big integers
    issuer: Name,
    subject: Name,
    not_before: DateTime<Utc>,//i64,//SystemTime,                    // Using SystemTime for time representation
    not_after: DateTime<Utc>,//i64,//SystemTime,
    key_usage: KeyUsage,

    extensions: Vec<Extension>,          // Raw X.509 extensions
    extra_extensions: Vec<Extension>,    // Extensions to be copied raw into any marshaled certificates
    //unhandled_critical_extensions: Vec<asn1::ObjectIdentifier>, // List of extension IDs not fully processed

    ext_key_usage: Vec<ExtKeyUsage>,           // Sequence of extended key usages
    unknown_ext_key_usage: Vec<Vec<i32>>,//unknown_ext_key_usage: Vec<asn1::ObjectIdentifier>, // Encountered extended key usages unknown to this package

    basic_constraints_valid: bool,              // Indicates if BasicConstraints are valid
    is_ca: bool,
    max_path_len: i32,                         // MaxPathLen for BasicConstraints
    max_path_len_zero: bool,                   // Indicates if MaxPathLen is explicitly zero
    subject_key_id: Vec<u8>,
    authority_key_id: Vec<u8>,
    ocsp_server: Vec<String>,                   // Authority Information Access
    issuing_certificate_url: Vec<String>,

    dns_names: Vec<String>,                     // Subject Alternate Name values
    email_addresses: Vec<String>,
    ip_addresses: Vec<net::IpAddr>,            // IP addresses
    //uris: Vec<url::Url>,                       // Assuming url is a module with Url struct

    permitted_dns_domains_critical: bool,
    permitted_dns_domains: Vec<String>,
    excluded_dns_domains: Vec<String>,
    //permitted_ip_ranges: Vec<IpNet>, // Assuming IpNet is defined
    //excluded_ip_ranges: Vec<IpNet>,
    permitted_email_addresses: Vec<String>,
    excluded_email_addresses: Vec<String>,
    permitted_uri_domains: Vec<String>,
    excluded_uri_domains: Vec<String>,

    crl_distribution_points: Vec<String>,
    policy_identifiers: Vec<Vec<i32>>, // policy_identifiers: Vec<asn1::ObjectIdentifier>,
    //policies: Vec<OID>, // Assuming OID is defined
}

impl Certificate {
    //
    fn check_signature_from(&mut self, parent: &Certificate) -> bool { // fn (c *Certificate) Check_signature_from(parent *Certificate) error
        // RFC 5280, 4.2.1.9:
        // "If the basic constraints extension is not present in a version 3
        // certificate, or the extension is present but the cA boolean is not
        // asserted, then the certified public key MUST NOT be used to verify
        // certificate signatures."
        if parent.version == 3 && !parent.basic_constraints_valid ||
		parent.basic_constraints_valid && !parent.is_ca {
            return false; //return ConstraintViolationError{}
        }

        if parent.key_usage.0 != 0 && parent.key_usage.0 & KeyUsage::CERT_SIGN.0 == 0 {
            return false; // return ConstraintViolationError{}
        }

        if parent.public_key_algorithm == PublicKeyAlgorithm::UnknownPublicKeyAlgorithm {
            return false; //return ErrUnsupportedAlgorithm
        }

        // return checkSignature(c.SignatureAlgorithm, c.RawTBSCertificate, c.Signature, parent.PublicKey, false);
        return check_signature(&self.signature_algorithm, &self.raw_tbs_certificate, &self.signature, &parent.public_key, false);
    }
}

// CheckSignature verifies that signature is a valid signature over signed from
// c's public key.
//
// This is a low-level API that performs no validity checks on the certificate.
//
// [MD5WithRSA] signatures are rejected, while [SHA1WithRSA] and [ECDSAWithSHA1]
// signatures are currently accepted.
fn check_signature(algo: &SignatureAlgorithm, signed: &Vec<u8>, signature: &Vec<u8>, public_key: &PublicKey, allow_SHA1: bool) -> bool {

    let signature_algorithm_details: Vec<AlgorithmDetails> = vec![
        AlgorithmDetails {
            algo: SignatureAlgorithm::MD2WithRSA,
            name: String::from("MD2-RSA"),
            oid: OID_SIGNATURE_MD2_WITH_RSA.to_vec(),
            pub_key_algo: PublicKeyAlgorithm::RSA,
            hash: None, // no value for MD2
        },
        AlgorithmDetails {
            algo: SignatureAlgorithm::MD5WithRSA,
            name: String::from("MD5-RSA"),
            oid: OID_SIGNATURE_MD5_WITH_RSA.to_vec(),
            pub_key_algo: PublicKeyAlgorithm::RSA,
            hash: Some(String::from("MD5")),
        },
        AlgorithmDetails {
            algo: SignatureAlgorithm::SHA1WithRSA,
            name: String::from("SHA1-RSA"),
            oid: OID_SIGNATURE_SHA1_WITH_RSA.to_vec(),
            pub_key_algo: PublicKeyAlgorithm::RSA,
            hash: Some(String::from("SHA1")),
        },
        AlgorithmDetails {
            algo: SignatureAlgorithm::SHA256WithRSA,
            name: String::from("SHA256-RSA"),
            oid: OID_SIGNATURE_SHA256_WITH_RSA.to_vec(),
            pub_key_algo: PublicKeyAlgorithm::RSA,
            hash: Some(String::from("SHA256")),
        },
        AlgorithmDetails {
            algo: SignatureAlgorithm::SHA384WithRSA,
            name: String::from("SHA384-RSA"),
            oid: OID_SIGNATURE_SHA384_WITH_RSA.to_vec(),
            pub_key_algo: PublicKeyAlgorithm::RSA,
            hash: Some(String::from("SHA384")),
        },
        AlgorithmDetails {
            algo: SignatureAlgorithm::SHA512WithRSA,
            name: String::from("SHA512-RSA"),
            oid: OID_SIGNATURE_SHA512_WITH_RSA.to_vec(),
            pub_key_algo: PublicKeyAlgorithm::RSA,
            hash: Some(String::from("SHA512")),
        },
        AlgorithmDetails {
            algo: SignatureAlgorithm::SHA256WithRSAPSS,
            name: String::from("SHA256-RSAPSS"),
            oid: OID_SIGNATURE_RSA_PSS.to_vec(),
            pub_key_algo: PublicKeyAlgorithm::RSA,
            hash: Some(String::from("SHA256")),
        },
        AlgorithmDetails {
            algo: SignatureAlgorithm::SHA384WithRSAPSS,
            name: String::from("SHA384-RSAPSS"),
            oid: OID_SIGNATURE_RSA_PSS.to_vec(),
            pub_key_algo: PublicKeyAlgorithm::RSA,
            hash: Some(String::from("SHA384")),
        },
        AlgorithmDetails {
            algo: SignatureAlgorithm::SHA512WithRSAPSS,
            name: String::from("SHA512-RSAPSS"),
            oid: OID_SIGNATURE_RSA_PSS.to_vec(),
            pub_key_algo: PublicKeyAlgorithm::RSA,
            hash: Some(String::from("SHA512")),
        },
        AlgorithmDetails {
            algo: SignatureAlgorithm::DSAWithSHA1,
            name: String::from("DSA-SHA1"),
            oid: OID_SIGNATURE_DSA_WITH_SHA1.to_vec(),
            pub_key_algo: PublicKeyAlgorithm::DSA,
            hash: Some(String::from("SHA1")),
        },
        AlgorithmDetails {
            algo: SignatureAlgorithm::DSAWithSHA256,
            name: String::from("DSA-SHA256"),
            oid: OID_SIGNATURE_DSA_WITH_SHA256.to_vec(),
            pub_key_algo: PublicKeyAlgorithm::DSA,
            hash: Some(String::from("SHA256")),
        },
        AlgorithmDetails {
            algo: SignatureAlgorithm::ECDSAWithSHA1,
            name: String::from("ECDSA-SHA1"),
            oid: OID_SIGNATURE_ECDSA_WITH_SHA1.to_vec(),
            pub_key_algo: PublicKeyAlgorithm::ECDSA,
            hash: Some(String::from("SHA1")),
        },
        AlgorithmDetails {
            algo: SignatureAlgorithm::ECDSAWithSHA256,
            name: String::from("ECDSA-SHA256"),
            oid: OID_SIGNATURE_ECDSA_WITH_SHA256.to_vec(),
            pub_key_algo: PublicKeyAlgorithm::ECDSA,
            hash: Some(String::from("SHA256")),
        },
        AlgorithmDetails {
            algo: SignatureAlgorithm::ECDSAWithSHA384,
            name: String::from("ECDSA-SHA384"),
            oid: OID_SIGNATURE_ECDSA_WITH_SHA384.to_vec(),
            pub_key_algo: PublicKeyAlgorithm::ECDSA,
            hash: Some(String::from("SHA384")),
        },
        AlgorithmDetails {
            algo: SignatureAlgorithm::ECDSAWithSHA512,
            name: String::from("ECDSA-SHA512"),
            oid: OID_SIGNATURE_ECDSA_WITH_SHA512.to_vec(),
            pub_key_algo: PublicKeyAlgorithm::ECDSA,
            hash: Some(String::from("SHA512")),
        },
        AlgorithmDetails {
            algo: SignatureAlgorithm::PureEd25519,
            name: String::from("Ed25519"),
            oid: OID_SIGNATURE_ED25519.to_vec(),
            pub_key_algo: PublicKeyAlgorithm::Ed25519,
            hash: Some(String::from("")),
        },
    ];

    let mut hash_type = None;
	let mut pub_key_algo = PublicKeyAlgorithm::UnknownPublicKeyAlgorithm;

    for details in signature_algorithm_details {
        if details.algo == *algo {
            hash_type = details.hash;
            pub_key_algo = details.pub_key_algo;
            break;
        }
    }

    //match hash_type.unwrap() {
        //"MD5" => ... ,
        //"SHA1" => ... ,
        //_ => ... ,
    //}

    match public_key {
        PublicKey::RsaPublicKey(rsa_pub_key) => {
            if pub_key_algo != PublicKeyAlgorithm::RSA {
                return false; // signaturePublicKeyAlgoMismatchError(pubKeyAlgo, pub)
            }
            if algo.is_rsa_pss() {
                let pss_options = rsa::PSSOptions{salt_length: rsa::PSSSaltLengthEqualsHash, hash: 0 };
                return rsa::verify_pss(rsa_pub_key, 256, signed, signature, &pss_options);
            } else {
                // return rsa::verify_pkcs1v15(rsa_pub_key, hash_type, signed, signature);
                return rsa::verify_pkcs1v15(rsa_pub_key, 256, signed, signature);
            }
        },
        PublicKey::ECDSAPublicKey(ecdsa_pub_key) => {
            if pub_key_algo != PublicKeyAlgorithm::ECDSA {
                return false;
            }
            if !ecdsa_verify_asn1(ecdsa_pub_key, signed, signature) {
                return false; // "x509: ECDSA verification failure")
            }
            return true;
        },
        PublicKey::ED25519PublicKey(ed25519_pub_key) => {
            if pub_key_algo != PublicKeyAlgorithm::Ed25519 {
                return false;
            }
            if !ed25519::verify(ed25519_pub_key, signed, signature) {
                return false; // "x509: Ed25519 verification failure")
            }
            return true;
        },
        _ => return false,
    }
}

fn ecdsa_verify_asn1(pub_key: &ecdsa::PublicKey, signed: &[u8], signature: &Vec<u8>) -> bool {
    if let Some((r_bytes, s_bytes)) = parse_signature(&signature) {
        //
        let c = pub_key.curve.params();

        //let q = *c.point_from_affine();

        let r = BigInt::from_bytes_be(Sign::Plus, &r_bytes);
        let s = BigInt::from_bytes_be(Sign::Plus, &s_bytes);

        if !ecdsa::verify(&pub_key, &signed, &r, &s) {
            return false;
        }

        return true;
    }
    else {
        return false;
    }
}

fn parse_signature(sig: &Vec<u8>) -> Option<(Vec<u8>, Vec<u8>)> { // fn parse_signature(sig: &[u8]) -> (r, s []byte, err error) {
	let mut inner = ASN1String{ 0: Vec::new()}; //var inner cryptobyte.String

    let mut r: Vec<u8> = Vec::new();
    let mut s: Vec<u8> = Vec::new();
	let mut input = ASN1String{ 0: sig.clone()}; // input := cryptobyte.String(sig)
	if !input.read_asn1(&mut inner, SEQUENCE) ||   // if !input.ReadASN1(&inner, asn1.SEQUENCE) ||
		!input.0.is_empty() ||  //  !input.Empty() ||
		!inner.read_asn1_bytes(&mut r) || // !inner.ReadASN1Integer(&r) ||
		!inner.read_asn1_bytes(&mut s) || // !inner.ReadASN1Integer(&s) ||
		!inner.0.is_empty() { // !inner.Empty() {
		return None; //return nil, nil, errors.New("invalid ASN.1")
	}
	return Some((r, s)); //return r, s, nil
}

fn parse_certificate(der: &[u8]) -> Certificate { // fn parse_certificate(der: &[u8]) -> Result<Certificate, Box<dyn Error>> {
    //
    let mut cert = Certificate {
        raw: Vec::new(),
        raw_tbs_certificate: Vec::new(),
        raw_subject_public_key_info: Vec::new(),
        raw_subject: Vec::new(),
        raw_issuer: Vec::new(),
        signature: Vec::new(),
        signature_algorithm: SignatureAlgorithm::UnknownSignatureAlgorithm, // Default value
        public_key_algorithm: PublicKeyAlgorithm::UnknownPublicKeyAlgorithm, // Default value
        public_key: PublicKey::UnknownPubicKey,
        version: 0,
        serial_number: BigInt::default(),
        issuer: Name::default(), // Assuming a default implementation
        subject: Name::default(),
        not_before: DateTime::<Utc>::MIN_UTC, //0i64,//SystemTime::now(),
        not_after: DateTime::<Utc>::MAX_UTC,//SystemTime::now(),
        key_usage: KeyUsage::CERT_SIGN,
        extensions: Vec::new(),
        extra_extensions: Vec::new(),
        //unhandled_critical_extensions: Vec::new(),
        ext_key_usage: Vec::new(),
        unknown_ext_key_usage: Vec::new(),
        basic_constraints_valid: false,
        is_ca: false,
        max_path_len: 0,
        max_path_len_zero: false,
        subject_key_id: Vec::new(),
        authority_key_id: Vec::new(),
        ocsp_server: Vec::new(),
        issuing_certificate_url: Vec::new(),
        dns_names: Vec::new(),
        email_addresses: Vec::new(),
        ip_addresses: Vec::new(),
        //uris: Vec::new(),
        permitted_dns_domains_critical: false,
        permitted_dns_domains: Vec::new(),
        excluded_dns_domains: Vec::new(),
        //permitted_ip_ranges: Vec::new(),
        //excluded_ip_ranges: Vec::new(),
        permitted_email_addresses: Vec::new(),
        excluded_email_addresses: Vec::new(),
        permitted_uri_domains: Vec::new(),
        excluded_uri_domains: Vec::new(),
        crl_distribution_points: vec![],
        policy_identifiers: vec![],
        //policies: vec![]
    };

    let mut input = ASN1String{ 0: der.to_vec()};
    // we read the SEQUENCE including length and tag bytes so that
	// we can populate Certificate.Raw, before unwrapping the
	// SEQUENCE so it can be operated on

    // Чтение ASN.1 элемента
    let mut input1 = input.clone();

    println!("parseCertificate input before read_asn1_element is : {:?}", &input);

    if !input.read_asn1_element(&mut input1, SEQUENCE) {
        //return Err("x509: malformed certificate".into());
        panic!("x509: malformed certificate");
    }
    //println!("parseCertificate input after read_asn1_element is : {:?}", &input1);
    cert.raw = input1.0.clone();

    // Чтение основного элемента ASN.1
    if !input1.read_asn1(&mut input, SEQUENCE) {
        //return Err("x509: malformed certificate".into());
        panic!("x509: malformed certificate");
    }
    //println!("parseCertificate input after read_asn1 is : {:?}", &input);

    let mut tbs = ASN1String{ 0: Vec::new()}; // Подходящий тип для tbs

    if !input.read_asn1_element(&mut tbs, SEQUENCE) {
        //return Err("x509: malformed tbs certificate".into());
        panic!("x509: malformed tbs certificate");
    }
    //println!("parseCertificate tbs after read_asn1 is : {:?}", &tbs);
    cert.raw_tbs_certificate = tbs.0.clone();

    let mut tbs1 = tbs.clone();
    if !tbs.read_asn1(&mut tbs1, SEQUENCE) {
        //return Err("x509: malformed version".into());
        panic!("x509: malformed tbs certificate");
    }

    //println!("parseCertificate tbs1 after read_asn1 is : {:?}", &tbs1);

    // Чтение версии
    // if !tbs1.read_optional_asn1_integer(&mut cert.version, Tag(0).constructed().context_specific(), 0) {
    if !tbs1.read_optional_asn1_integer(&mut cert.version, context_specific(constructed(0u8)), 0) {
        //return Err("x509: malformed version".into());
        panic!("x509: malformed tbs certificate");
    }

    if cert.version < 0 {
        //return Err("x509: malformed version".into());
        panic!("x509: malformed version");
    }

    cert.version += 1;
    println!("parseCertificate cert.version is : {:?}", &cert.version);
    if cert.version > 3 {
        //return Err("x509: invalid version".into());
        panic!("x509: invalid version");
    }

    // Чтение серийного номера
    //let mut serial = BigInt::default(); // Эквивалент создания нового большого числа
    //if !tbs1.read_asn1_big_int(&mut serial) { // if !tbs1.read_asn1_integer(&mut tbs, &serial) {
        //return Err("x509: malformed serial number".into());
        //panic!("x509: malformed serial number");
    //}
    match tbs1.read_asn1_big_int(){
        Some(serial) => cert.serial_number = serial,
        None => panic!("x509: malformed serial number"),
    }
    //cert.serial_number = serial;

    // Чтение идентификатора алгоритма подписи
    let mut sig_ai_seq = ASN1String{ 0: Vec::new()};
    if !tbs1.read_asn1(&mut sig_ai_seq, SEQUENCE) {
        //return Err("x509: malformed signature algorithm identifier".into());
        panic!("x509: malformed signature algorithm identifier");
    }

    // Before parsing the inner algorithm identifier, extract
	// the outer algorithm identifier and make sure that they
	// match.
    let mut outer_sig_ai_seq = ASN1String{ 0: Vec::new()};
    if !input.read_asn1(&mut outer_sig_ai_seq, SEQUENCE) {
        //return Err("x509: malformed algorithm identifier".into());
        panic!("x509: malformed algorithm identifier");
    }
    println!("parseCertificate sig_ai_seq.0 is : {:?}", &sig_ai_seq.0);
    println!("parseCertificate outer_sig_ai_seq.0 is : {:?}", &outer_sig_ai_seq.0);
    if outer_sig_ai_seq.0 != sig_ai_seq.0 { // if outer_sig_ai_seq != sig_ai_seq {
        //return Err("x509: inner and outer signature algorithm identifiers don't match".into());
        panic!("x509: inner and outer signature algorithm identifiers don't match");
    }

    let sig_ai = parse_ai(&mut sig_ai_seq); // Обработка идентификатора алгоритма
    cert.signature_algorithm = get_signature_algorithm_from_ai(sig_ai);
    println!("parseCertificate cert.signature_algorithm is : {:?}", &cert.signature_algorithm);

    // Чтение секвенции издателя
    let mut issuer_seq = ASN1String{ 0: Vec::new()};
    if !tbs1.read_asn1_element(&mut issuer_seq, SEQUENCE) {
        //return Err("x509: malformed issuer".into());
        panic!("x509: malformed issuer");
    }
    println!("parseCertificate issuer_seq.0 is : {:?}", &issuer_seq.0);
    cert.raw_issuer = issuer_seq.0.clone();
    let issuer_rdns = parse_name(&mut issuer_seq);
    cert.issuer.fill_from_rdn_sequence(&issuer_rdns);

    let mut validity = ASN1String{ 0: Vec::new()};
	if !tbs1.read_asn1(&mut validity, SEQUENCE) {
		panic!("x509: malformed validity");
	}

    (cert.not_before, cert.not_after) = parse_validity(& mut validity).unwrap();

    println!("parseCertificate cert.not_before is : {:?}", &cert.not_before);
    println!("parseCertificate cert.not_after is : {:?}", &cert.not_after);
	//cert.not_before, cert.not_after, err = parseValidity(validity);
	//if err != nil {
		//return nil, err
	//}

    let mut subject_seq = ASN1String{ 0: Vec::new()};
	if !tbs1.read_asn1_element(&mut subject_seq, SEQUENCE) {
		panic!("x509: malformed issuer");
	}
	cert.raw_subject = subject_seq.0.clone();
    println!("parseCertificate cert.raw_subject is : {:?}", &cert.raw_subject);
    let subject_rdns = parse_name(&mut subject_seq);

	cert.subject.fill_from_rdn_sequence(&subject_rdns);

    let mut spki = ASN1String{ 0: Vec::new()};
	if !tbs1.read_asn1_element(&mut spki, SEQUENCE) {
		panic!("x509: malformed spki");
	}
	cert.raw_subject_public_key_info = spki.0.clone();
    let mut spki1 = ASN1String{ 0: Vec::new()};
	if !spki.read_asn1(&mut spki1, SEQUENCE) {
		panic!("x509: malformed spki"); //return nil, errors.New("x509: malformed spki")
	}
	let mut pk_ai_seq = ASN1String{ 0: Vec::new()};
	if !spki1.read_asn1(&mut pk_ai_seq, SEQUENCE) {
		panic!("x509: malformed public key algorithm identifier");
	}

    let pk_ai = parse_ai(&mut pk_ai_seq);//pkAI, err := parseAI(pkAISeq)
    //if err != nil {
		//return nil, err
	//}
	cert.public_key_algorithm = get_public_key_algorithm_from_oid(&pk_ai.algorithm);
    println!("parseCertificate cert.public_key_algorithm is : {:?}", &cert.public_key_algorithm);
	let mut spk = BitString{bytes: Vec::new(), bit_length: 0};//var spk asn1.BitString
	if !spki1.read_asn1_bitstring(&mut spk) {
		panic!("x509: malformed subjectPublicKey");
	}
	if cert.public_key_algorithm != PublicKeyAlgorithm::UnknownPublicKeyAlgorithm {

        let public_key_info = PublicKeyInfo{algorithm: pk_ai, publicKey: spk};
        cert.public_key = parse_public_key(&public_key_info);
		//cert.PublicKey, err = parsePublicKey(&publicKeyInfo{
			//Algorithm: pkAI,
			//PublicKey: spk,
		//})
		//if err != nil {
			//return nil, err
		//}
	}


    if cert.version > 1 {
        if !tbs1.skip_optional_asn1(context_specific(1u8)) {
            panic!("x509: malformed issuerUniqueID");
        }
        if !tbs1.skip_optional_asn1(context_specific(2u8)) {
            panic!("x509: malformed subjectUniqueID");
        }

        if cert.version == 3 {
            let mut extensions = ASN1String{ 0: Vec::new()};
			let mut present = false;
            if !tbs1.read_optional_asn1(&mut extensions, &mut present, context_specific(constructed(3u8))) {
                panic!("x509: malformed extensions");
            }

            if present {
                let mut seen_exts: HashMap<String, bool> = HashMap::new(); // seenExts := make(map[string]bool)
                let mut extensions1 = ASN1String{ 0: Vec::new()};
                if !extensions.read_asn1(&mut extensions1, SEQUENCE) {
                    panic!("x509: malformed extensions");
                }

                while !extensions.0.is_empty() {
                    let mut extension = ASN1String{ 0: Vec::new()};
                    if !extensions.read_asn1(&mut extension, SEQUENCE) {
                        panic!("x509: malformed extension");
                    }
                    let ext = parse_extension(&mut extension); //ext, err := parseExtension(extension)
					//if err != nil {
						//return nil, err
					//}

                    let oid_str = to_oid_string(&ext.id); //oidStr := ext.Id.String()
                    if *seen_exts.get(&oid_str).unwrap() {
                        panic!("x509: certificate contains duplicate extensions");
                    }
					//if seenExts[oidStr] {
						//return nil, errors.New("x509: certificate contains duplicate extensions")
					//}
					seen_exts.insert(oid_str, true); //seenExts[oidStr] = true
                    cert.extensions.push(ext);
                }

                //err = processExtensions(cert)
				//if err != nil {
					//return nil, err
				//}
            }
        }
    }

    let mut signature = BitString{ bytes: vec![], bit_length: 0 } ;
	if !input.read_asn1_bitstring(&mut signature) {
		panic!("x509: malformed signature");
	}
    cert.signature = signature.right_align();

    cert

}

fn to_oid_string(data: &Vec<i32>) -> String{
    let mut s = String::new();
    let mut first = true;

    for &v in data.iter() {
        if !first {
            s.push('.');
        }
        s.push_str(&v.to_string());
        first = false;
    }
    s
}


#[derive(Debug, Clone)]
struct AttributeTypeAndValue {
    atype: Vec<i32>,
    value: String,
}


//struct RDN_sequence {

//};// []RelativeDistinguishedNameSET

//struct RelativeDistinguishedNameSET (
    //Vec<AttributeTypeAndValue>,
//);


// parseName parses a DER encoded Name as defined in RFC 5280. We may
// want to export this function in the future for use in crypto/tls.
pub fn parse_name(raw: &mut ASN1String) -> Vec<Vec<AttributeTypeAndValue>> { // pub fn parse_name(raw: &mut ASN1String) -> RDN_sequence {
    //
    let mut der = ASN1String{ 0: Vec::new()};
    if !raw.read_asn1(&mut der, SEQUENCE) {
        panic!("x509: invalid RDNSequence");
    }

    let mut rdn_seq: Vec<Vec<AttributeTypeAndValue>> = Vec::new(); // let mut rdn_seq: RDNSequence;
    if !raw.0.is_empty(){
        let mut rdn_set: Vec<AttributeTypeAndValue> = Vec::new(); // let mut rdn_set: RelativeDistinguishedNameSET;
        let mut set = ASN1String{ 0: Vec::new()};
        if !raw.read_asn1(&mut set, SET) {
			//return nil, errors.New("x509: invalid RDNSequence")
            panic!("x509: invalid RDNSequence");
		}

        while !set.0.is_empty() {
            let mut atav = ASN1String{ 0: Vec::new()};
            if !set.read_asn1(&mut atav, SEQUENCE) {
                panic!("x509: invalid RDNSequence: invalid attribute");
            }

            let mut attr: AttributeTypeAndValue = AttributeTypeAndValue{atype: Vec::new(), value: String::new()};
            if !atav.read_asn1_object_identifier(&mut attr.atype) {
                panic!("x509: invalid RDNSequence: invalid attribute type");
            }

            let mut raw_value = ASN1String{ 0: Vec::new()};
			let mut value_tag = 0u8;
            if !atav.read_any_asn1(&mut raw_value, &mut value_tag) {
                panic!("x509: invalid RDNSequence: invalid attribute value");
            }

            //(attr.Value, err) = parse_asn1_string(valueTag, rawValue);
            //if err != nil {
				//panic!("x509: invalid RDNSequence: invalid attribute value: %s", err);
			//}
            attr.value = parse_asn1_string(value_tag, &raw_value.0).expect("x509: invalid RDNSequence: invalid attribute value: %s");

            rdn_set.push(attr);

        }
        rdn_seq.push(rdn_set);
    }

    return rdn_seq;
}

// pub fn parse_asn1_string(tag: u8, value: &[u8]) -> Result<String, ASN1Error> {
pub fn parse_asn1_string(tag: u8, value: &[u8]) -> Option<String> {
    match tag {
        T61_STRING => Some(String::from_utf8_lossy(value).to_string()),//Ok(String::from_utf8_lossy(value).to_string()),
        PRINTABLE_STRING => {
            for &b in value {
                if !is_printable(b) {
                    return None; //return Err(ASN1Error::InvalidPrintableString);
                }
            }
            Some(String::from_utf8_lossy(value).to_string()) // Ok(String::from_utf8_lossy(value).to_string())
        }
        UTF8_STRING => {
            if !is_valid_utf8(&value) {
                return None; //return Err(ASN1Error::InvalidUTF8String);
            }
            Some(String::from_utf8_lossy(value).to_string()) // Ok(String::from_utf8_lossy(value).to_string())
        }
        BMP_STRING => {
            if value.len() % 2 != 0 {
                return None; // return Err(ASN1Error::InvalidBMPString);
            }

            let mut decoded = Vec::new();
            let mut iter = value.chunks_exact(2);
            for chunk in iter {
                let code_unit = ((chunk[0] as u16) << 8) | (chunk[1] as u16);
                decoded.push(code_unit);
            }

            // Strip terminator if present.
            if decoded.len() >= 2 && decoded[decoded.len() - 1] == 0 && decoded[decoded.len() - 2] == 0 {
                decoded.pop();
                decoded.pop();
            }

            // Convert u16 vector to String
            match String::from_utf16(&decoded) {
                Ok(string) => return Some(string),
                Err(_) => return None,
            }

            //return Some(String::from_utf16(&decoded)?); // return Ok(String::from_utf16(&decoded).map_err(|_| ASN1Error::InvalidBMPString)?);
        }
        IA5_STRING => {
            let s = String::from_utf8_lossy(value).to_string();
            if is_ia5_string(&s) {
                return None; //return Err(ASN1Error::InvalidIA5String);
            }
            Some(s) //Ok(s)
        }
        NUMERIC_STRING => {
            for &b in value {
                if !('0' as u8 <= b && b <= '9' as u8 || b == ' ' as u8) {
                    return None; // return Err(ASN1Error::InvalidNumericString);
                }
            }
            Some(String::from_utf8_lossy(value).to_string()) // Ok(String::from_utf8_lossy(value).to_string())
        }
        _ => None,//Err(ASN1Error::UnsupportedStringType),
    }
}

// Helper functions to validate characters and UTF-8
fn is_printable(b: u8) -> bool {
    (b'b' >= b'a' && b <= b'z') || (b >= b'A' && b <= b'Z') ||
    (b >= b'0' && b <= b'9') || (b >= b'\'' && b <= b')') ||
    (b >= b'+' && b <= b'/') || b == b' ' ||
    b == b':' || b == b'=' || b == b'?' ||
    b == b'*' || b == b'&'
}

fn is_valid_utf8(value: &[u8]) -> bool {
    // Fast path for ASCII
    for &byte in value {
        if byte >= 0x80 {
            return false;
        }
    }
    true
}

//const MAX_ASCII: char = 'u{007F}';

fn is_ia5_string(s: &str) -> bool {
    for r in s.chars() {
        // Per RFC5280 "IA5String is limited to the set of ASCII characters"
        if r > 127 as char { // if r > MAX_ASCII {
            return false;
        }
    }
    return true;
}



// ASN.1 types

#[derive(Debug, Clone)]
pub struct RawValue {
    class: i32,       // ASN.1 class (e.g. Universal, Application, Context-specific, Private)
    tag: i32,         // ASN.1 tag
    is_compound: bool, // Indicates if the RawValue is a compound type
    bytes: Vec<u8>,   // Undecoded bytes of the ASN.1 object
    full_bytes: Vec<u8>, // Complete bytes including the tag and length
}

#[derive(Debug, Clone)]
struct AlgorithmIdentifier {
    algorithm: Vec<i32>,
    parameters: Option<RawValue>
}

pub fn parse_ai(der: &mut ASN1String) -> AlgorithmIdentifier {
    let mut algorithm: Vec<i32> = Vec::new();

    let mut parameters = RawValue {
        class: 0,
        tag: 0,
        is_compound: false,
        bytes: Vec::new(),
        full_bytes: Vec::new(),
    };

    if !der.read_asn1_object_identifier(&mut algorithm){
        panic!("x509: malformed OID");
    }

    if der.0.is_empty(){
        return AlgorithmIdentifier { algorithm, parameters: Some(parameters) };
    }

    let mut params = ASN1String{ 0: Vec::new()};
    let mut tag = 0u8;

    if !der.read_any_asn1_element(&mut params, &mut tag) {
        panic!("x509: malformed parameters");
	}

    parameters.tag = tag as i32;
    parameters.full_bytes = params.0.to_vec();

    return AlgorithmIdentifier { algorithm, parameters: Some(parameters) }
}

fn get_signature_algorithm_from_ai(ai: AlgorithmIdentifier) -> SignatureAlgorithm {
    if ai.algorithm == OID_SIGNATURE_ED25519.to_vec() {
        // RFC 8410, Section 3
		// > For all of the OIDs, the parameters MUST be absent.
        if ai.parameters.unwrap().full_bytes.len() != 0 {
            return SignatureAlgorithm::UnknownSignatureAlgorithm;
        }
    }

    let signature_algorithm_details: Vec<AlgorithmDetails> = vec![
        AlgorithmDetails {
            algo: SignatureAlgorithm::MD2WithRSA,
            name: String::from("MD2-RSA"),
            oid: OID_SIGNATURE_MD2_WITH_RSA.to_vec(),
            pub_key_algo: PublicKeyAlgorithm::RSA,
            hash: None, // no value for MD2
        },
        AlgorithmDetails {
            algo: SignatureAlgorithm::MD5WithRSA,
            name: String::from("MD5-RSA"),
            oid: OID_SIGNATURE_MD5_WITH_RSA.to_vec(),
            pub_key_algo: PublicKeyAlgorithm::RSA,
            hash: Some(String::from("MD5")),
        },
        AlgorithmDetails {
            algo: SignatureAlgorithm::SHA1WithRSA,
            name: String::from("SHA1-RSA"),
            oid: OID_SIGNATURE_SHA1_WITH_RSA.to_vec(),
            pub_key_algo: PublicKeyAlgorithm::RSA,
            hash: Some(String::from("SHA1")),
        },
        AlgorithmDetails {
            algo: SignatureAlgorithm::SHA256WithRSA,
            name: String::from("SHA256-RSA"),
            oid: OID_SIGNATURE_SHA256_WITH_RSA.to_vec(),
            pub_key_algo: PublicKeyAlgorithm::RSA,
            hash: Some(String::from("SHA256")),
        },
        AlgorithmDetails {
            algo: SignatureAlgorithm::SHA384WithRSA,
            name: String::from("SHA384-RSA"),
            oid: OID_SIGNATURE_SHA384_WITH_RSA.to_vec(),
            pub_key_algo: PublicKeyAlgorithm::RSA,
            hash: Some(String::from("SHA384")),
        },
        AlgorithmDetails {
            algo: SignatureAlgorithm::SHA512WithRSA,
            name: String::from("SHA512-RSA"),
            oid: OID_SIGNATURE_SHA512_WITH_RSA.to_vec(),
            pub_key_algo: PublicKeyAlgorithm::RSA,
            hash: Some(String::from("SHA512")),
        },
        AlgorithmDetails {
            algo: SignatureAlgorithm::SHA256WithRSAPSS,
            name: String::from("SHA256-RSAPSS"),
            oid: OID_SIGNATURE_RSA_PSS.to_vec(),
            pub_key_algo: PublicKeyAlgorithm::RSA,
            hash: Some(String::from("SHA256")),
        },
        AlgorithmDetails {
            algo: SignatureAlgorithm::SHA384WithRSAPSS,
            name: String::from("SHA384-RSAPSS"),
            oid: OID_SIGNATURE_RSA_PSS.to_vec(),
            pub_key_algo: PublicKeyAlgorithm::RSA,
            hash: Some(String::from("SHA384")),
        },
        AlgorithmDetails {
            algo: SignatureAlgorithm::SHA512WithRSAPSS,
            name: String::from("SHA512-RSAPSS"),
            oid: OID_SIGNATURE_RSA_PSS.to_vec(),
            pub_key_algo: PublicKeyAlgorithm::RSA,
            hash: Some(String::from("SHA512")),
        },
        AlgorithmDetails {
            algo: SignatureAlgorithm::DSAWithSHA1,
            name: String::from("DSA-SHA1"),
            oid: OID_SIGNATURE_DSA_WITH_SHA1.to_vec(),
            pub_key_algo: PublicKeyAlgorithm::DSA,
            hash: Some(String::from("SHA1")),
        },
        AlgorithmDetails {
            algo: SignatureAlgorithm::DSAWithSHA256,
            name: String::from("DSA-SHA256"),
            oid: OID_SIGNATURE_DSA_WITH_SHA256.to_vec(),
            pub_key_algo: PublicKeyAlgorithm::DSA,
            hash: Some(String::from("SHA256")),
        },
        AlgorithmDetails {
            algo: SignatureAlgorithm::ECDSAWithSHA1,
            name: String::from("ECDSA-SHA1"),
            oid: OID_SIGNATURE_ECDSA_WITH_SHA1.to_vec(),
            pub_key_algo: PublicKeyAlgorithm::ECDSA,
            hash: Some(String::from("SHA1")),
        },
        AlgorithmDetails {
            algo: SignatureAlgorithm::ECDSAWithSHA256,
            name: String::from("ECDSA-SHA256"),
            oid: OID_SIGNATURE_ECDSA_WITH_SHA256.to_vec(),
            pub_key_algo: PublicKeyAlgorithm::ECDSA,
            hash: Some(String::from("SHA256")),
        },
        AlgorithmDetails {
            algo: SignatureAlgorithm::ECDSAWithSHA384,
            name: String::from("ECDSA-SHA384"),
            oid: OID_SIGNATURE_ECDSA_WITH_SHA384.to_vec(),
            pub_key_algo: PublicKeyAlgorithm::ECDSA,
            hash: Some(String::from("SHA384")),
        },
        AlgorithmDetails {
            algo: SignatureAlgorithm::ECDSAWithSHA512,
            name: String::from("ECDSA-SHA512"),
            oid: OID_SIGNATURE_ECDSA_WITH_SHA512.to_vec(),
            pub_key_algo: PublicKeyAlgorithm::ECDSA,
            hash: Some(String::from("SHA512")),
        },
        AlgorithmDetails {
            algo: SignatureAlgorithm::PureEd25519,
            name: String::from("Ed25519"),
            oid: OID_SIGNATURE_ED25519.to_vec(),
            pub_key_algo: PublicKeyAlgorithm::Ed25519,
            hash: Some(String::from("")),
        },
    ];

    if ai.algorithm != OID_SIGNATURE_RSA_PSS.to_vec() {
        for details in signature_algorithm_details {
            if ai.algorithm == details.oid {
                return details.algo;
            }
        }
        return SignatureAlgorithm::UnknownSignatureAlgorithm;
    }

    // RSA PSS is special because it encodes important parameters
	// in the Parameters.
    //let params: PssParameters;
    //if unmarshal(ai.parameters.full_bytes, &params){
        //return SignatureAlgorithm::UnknownSignatureAlgorithm;
    //}

    //let mgf1_hash_func: AlgorithmIdentifier;
    //if unmarshal(params.mgf.parameters.full_bytes, &mgf1_hash_func){
        //return SignatureAlgorithm::UnknownSignatureAlgorithm;
    //}

    // PSS is greatly overburdened with options. This code forces them into
	// three buckets by requiring that the MGF1 hash function always match the
	// message hash function (as recommended in RFC 3447, Section 8.1), that the
	// salt length matches the hash length, and that the trailer field has the
	// default value.

    //if (!params.hash.parameters.unwrap().full_bytes.is_empty() && !params.hash.parameters.unwrap().full_bytes.to_vec()==NullBytes.to_vec() ) ||
		//params.mgf.algorithm != oidMGF1 ||
		//mgf1_hash_func.algorithm != params.hash.algorithm ||
        //( mgf1_hash_func.parameters.unwrap().full_bytes.len() != 0 && mgf1_hash_func.parameters.unwrap().full_bytes != NullBytes ) ||
		//params.TrailerField != 1 {
		//return SignatureAlgorithm::UnknownSignatureAlgorithm;
	//}

    //match (params.hash.algorithm, params.salt_length) {
        //(OID_SHA256, 32) => SignatureAlgorithm::SHA256WithRSAPSS,
        //(OID_SHA384, 48) => SignatureAlgorithm::SHA384WithRSAPSS,
        //(OID_SHA512, 64) => SignatureAlgorithm::SHA512WithRSAPSS,
        //_ => SignatureAlgorithm::UnknownSignatureAlgorithm,
    //}

    return SignatureAlgorithm::UnknownSignatureAlgorithm;
}

// RFC 3279, 2.3 Public Key Algorithms
//
//	pkcs-1 OBJECT IDENTIFIER ::== { iso(1) member-body(2) us(840)
//		rsadsi(113549) pkcs(1) 1 }
//
// rsaEncryption OBJECT IDENTIFIER ::== { pkcs1-1 1 }
//
//	id-dsa OBJECT IDENTIFIER ::== { iso(1) member-body(2) us(840)
//		x9-57(10040) x9cm(4) 1 }
const	OID_PUBLIC_KEY_RSA: [i32; 7] = [1, 2, 840, 113549, 1, 1, 1];
const	OID_PUBLIC_KEY_DSA: [i32; 6] = [1, 2, 840, 10040, 4, 1];
// RFC 5480, 2.1.1 Unrestricted Algorithm Identifier and Parameters
//
//	id-ecPublicKey OBJECT IDENTIFIER ::= {
//		iso(1) member-body(2) us(840) ansi-X9-62(10045) keyType(2) 1 }
const	OID_PUBLIC_KEY_ECDSA: [i32; 6] = [1, 2, 840, 10045, 2, 1];
// RFC 8410, Section 3
//
//	id-X25519    OBJECT IDENTIFIER ::= { 1 3 101 110 }
//	id-Ed25519   OBJECT IDENTIFIER ::= { 1 3 101 112 }
const	OID_PUBLIC_KEY_X25519: [i32; 4]  = [1, 3, 101, 110];
const	OID_PUBLIC_KEY_ED25519: [i32; 4] = [1, 3, 101, 112];

fn get_public_key_algorithm_from_oid(oid: &Vec<i32>) -> PublicKeyAlgorithm {
    let oid_slice = oid.as_slice();
    match oid_slice {
        val if val==OID_PUBLIC_KEY_RSA.as_slice() => PublicKeyAlgorithm::RSA,
        val if val==OID_PUBLIC_KEY_DSA.as_slice() => PublicKeyAlgorithm::DSA,
        val if val==OID_PUBLIC_KEY_ECDSA.as_slice() => PublicKeyAlgorithm::ECDSA,
        val if val==OID_PUBLIC_KEY_ED25519.as_slice() => PublicKeyAlgorithm::Ed25519,
        _ => PublicKeyAlgorithm::UnknownPublicKeyAlgorithm,
    }
}
/*
pub fn unmarshal(b: &[u8], val: &mut dyn std::any::Any) -> Option<&[u8]> {
    unmarshal_with_params(b, val, "")
}

pub fn unmarshal_with_params(b: &[u8], val: &mut dyn std::any::Any, params: &str) -> Option<&[u8]> {
    //let v = val.downcast_mut::<&mut dyn std::any::Any>()
        //.ok_or(InvalidUnmarshalError { typ: std::any::TypeId::of::<&mut dyn std::any::Any>() })?;

    let (offset, rest) = parse_field(val, b, 0, parse_field_parameters(params))?;
    Some(&b[offset..])
}

fn parse_field(v: &mut dyn std::any::Any, bytes: &[u8], init_offset: usize, params: FieldParameters) -> Option<(usize, &[u8])> {
    let mut offset = init_offset;

    if offset == bytes.len() {
        if !set_default_value(v, &params) {
            //return Err(SyntaxError { message: "sequence truncated" });
        }
        return Some((offset, bytes));//return Ok((offset, bytes));
    }

    // Handle the ANY type.
    if let Some(iface) = v.downcast_ref::<&dyn std::any::Any>() {
        let (t, new_offset, err) = parse_tag_and_length(bytes, offset)?;
        if err.is_some() {
            return None; // return Err(err.unwrap());
        }

        // Check length and parse according to tag
        if is_invalid_length(new_offset, t.length, bytes.len()) {
            return None; //return Err(SyntaxError { message: "data truncated" });
        }

        let inner_bytes = &bytes[new_offset..new_offset + t.length];
        let result: Box<dyn std::any::Any> = match t.tag {
            Tag::PrintableString => parse_printable_string(inner_bytes)?,
            Tag::NumericString => parse_numeric_string(inner_bytes)?,
            Tag::IA5String => parse_ia5_string(inner_bytes)?,
            Tag::T61String => parse_t61_string(inner_bytes)?,
            Tag::UTF8String => parse_utf8_string(inner_bytes)?,
            Tag::Integer => parse_int64(inner_bytes)?,
            Tag::BitString => parse_bit_string(inner_bytes)?,
            Tag::OID => parse_object_identifier(inner_bytes)?,
            Tag::UTCTime => parse_utc_time(inner_bytes)?,
            Tag::GeneralizedTime => parse_generalized_time(inner_bytes)?,
            Tag::OctetString => inner_bytes.to_vec().into_boxed_slice(),
            Tag::BMPString => parse_bmp_string(inner_bytes)?,
            _ => Box::new(()), // Unknown type handling
        };

        // Update the reference
        mem::swap(v, &mut result);
        offset += t.length;
        return Some((offset, bytes));//Ok((offset, bytes));
    }

    // Normal case; parse according to the ASN.1 rules
    let (t, new_offset, err) = parse_tag_and_length(bytes, offset)?;
    if err.is_some() {
        return None;//return Err(err.unwrap());
    }

    Some((offset, bytes))
}*/

// fn parse_validity(der: &mut ASN1String) -> Option<(u64, u64)> {
fn parse_validity(der: &mut ASN1String) -> Option<(DateTime<Utc>, DateTime<Utc>)> {
	let not_before = parse_time(der);
	if not_before.is_none() {
		return None
	}
	let not_after = parse_time(der);
	if not_after.is_none() {
		return None;
	}

	return Some((not_before.unwrap(), not_after.unwrap()));
}

fn parse_time(der: &mut ASN1String) -> Option<DateTime<Utc> > {
    if der.peek_asn1_tag(TagUTCTime) {
        der.read_asn1_utc_time()
    } else if der.peek_asn1_tag(TagGeneralizedTime) {
        der.read_asn1_generalized_time()
    } else {
        None//Err("Unsupported time format".to_string())
    }
}

fn parse_extension(der: &mut ASN1String) -> Extension { // fn parse_extension(der: &mut ASN1String) -> (pkix.Extension, error) {
	let mut ext: Extension = Extension{ id: vec![], critical: None, value: vec![] };
	if !der.read_asn1_object_identifier(&mut ext.id) {
		panic!("x509: malformed extension OID field");
	}
    let mut ext_critical = false;
	if der.peek_asn1_tag(BOOLEAN) {
		if !der.read_asn1_boolean(&mut ext_critical) {
			panic!("x509: malformed extension critical field");
		}
        ext.critical = Some(ext_critical);
	}
    let mut val = ASN1String{ 0: Vec::new()};
	if !der.read_asn1(&mut val, OCTET_STRING) {
		panic!("x509: malformed extension value field");
	}
	ext.value = val.0;
	return ext;
}

struct PublicKeyInfo {
	//raw:       Vec<u8>,
	algorithm: AlgorithmIdentifier,
	publicKey: BitString,
}

#[derive(Debug, PartialEq)]
enum PublicKey {
    RsaPublicKey(rsa::PublicKey),
    ECDSAPublicKey(ecdsa::PublicKey),
    ED25519PublicKey(ed25519::PublicKey),
    X25519PublicKey,
    DsaPublicKey,
    UnknownPubicKey
}

// RFC 5480, 2.1.1.1. Named Curve
//
//	secp224r1 OBJECT IDENTIFIER ::= {
//	  iso(1) identified-organization(3) certicom(132) curve(0) 33 }
//
//	secp256r1 OBJECT IDENTIFIER ::= {
//	  iso(1) member-body(2) us(840) ansi-X9-62(10045) curves(3)
//	  prime(1) 7 }
//
//	secp384r1 OBJECT IDENTIFIER ::= {
//	  iso(1) identified-organization(3) certicom(132) curve(0) 34 }
//
//	secp521r1 OBJECT IDENTIFIER ::= {
//	  iso(1) identified-organization(3) certicom(132) curve(0) 35 }
//
// NB: secp256r1 is equivalent to prime256v1
const OID_NAMED_CURVE_P224: [i32;5] = [1, 3, 132, 0, 33];
const OID_NAMED_CURVE_P256: [i32;7] = [1, 2, 840, 10045, 3, 1, 7];
const OID_NAMED_CURVE_P384: [i32;5] = [1, 3, 132, 0, 34];
const OID_NAMED_CURVE_P521: [i32;5] = [1, 3, 132, 0, 35];


fn named_curve_from_oid(oid: &Vec<i32>) -> Option<ecdsa::Curve> {

    match oid.as_slice() {
        val if val==OID_NAMED_CURVE_P224.as_slice() => Some(ecdsa::p224()),
        val if val==OID_NAMED_CURVE_P256.as_slice() => Some(ecdsa::p256()),
        val if val==OID_NAMED_CURVE_P384.as_slice() => Some(ecdsa::p384()),
        val if val==OID_NAMED_CURVE_P521.as_slice() => Some(ecdsa::p521()),
        _ => None,
    }
	//switch {
	//case oid.Equal(oidNamedCurveP224):
		//return elliptic.P224()
	//case oid.Equal(oidNamedCurveP256):
		//return elliptic.P256()
	//case oid.Equal(oidNamedCurveP384):
		//return elliptic.P384()
	//case oid.Equal(oidNamedCurveP521):
		//return elliptic.P521()
	//}
	//return nil
}

fn parse_public_key(key_data: &PublicKeyInfo) -> PublicKey {
    let oid = &key_data.algorithm.algorithm;
	let params = key_data.algorithm.parameters.clone().unwrap().clone();
    let mut der = ASN1String{ 0: key_data.publicKey.right_align()}; // der = cryptobyte.String(key_data.publicKey.right_align() );
    match oid.as_slice() {
        val if val==OID_PUBLIC_KEY_RSA.as_slice() => {
            // RSA public keys must have a NULL in the parameters.
            // See RFC 3279, Section 2.3.1.
            if params.full_bytes != NullBytes.to_vec() {
                panic!("x509: RSA key missing NULL parameters");
            }

            let mut p = rsa::PublicKey{n: BigInt::from(0), e: 0i64};
            let mut der1 = ASN1String{ 0: Vec::new()};
            if !der.read_asn1(&mut der1, SEQUENCE) {
                panic!("x509: invalid RSA public key");
            }

            match der1.read_asn1_big_int() {
                Some(big_int) => p.n = big_int,
                None => panic!("x509: invalid RSA modulus"),
            }

            if !der1.read_asn1_i64(&mut p.e) {
                panic!("x509: invalid RSA public exponent");
            }

            if p.n.sign() == Sign::Minus {
                panic!("x509: RSA modulus is not a positive number");
            }
            if p.e <= 0i64 {
                panic!("x509: RSA public exponent is not a positive number");
            }

            return PublicKey::RsaPublicKey((p));
        },
        val if val==OID_PUBLIC_KEY_ECDSA.as_slice() => {
            let mut params_der = ASN1String{ 0: params.full_bytes.clone()};// cryptobyte.String(params.FullBytes)
            let mut named_curve_oid: Vec<i32> = Vec::new();
            if !params_der.read_asn1_object_identifier(&mut named_curve_oid) {
                panic!("x509: invalid ECDSA parameters");
            }
            //let named_curve = named_curve_from_oid(&named_curve_oid);
            match named_curve_from_oid(&named_curve_oid) {
                Some(named_curve) => {
                    //
                    let (x, y) : (BigInt, BigInt) = ecdsa::unmarshal(&named_curve, &der.0);
                    //if x == nil {
                        //panic!("x509: failed to unmarshal elliptic curve point");
                    //}
                    PublicKey::ECDSAPublicKey(ecdsa::PublicKey{curve: named_curve, x, y})
                },
                None => panic!("x509: unsupported elliptic curve"),
            }
        },
        val if val==OID_PUBLIC_KEY_ED25519.as_slice() => {
            // RFC 8410, Section 3
            // > For all of the OIDs, the parameters MUST be absent.
            if !params.full_bytes.is_empty() {
                panic!("x509: Ed25519 key encoded with illegal parameters");
            }
            if der.0.len() != ed25519::PUBLIC_KEY_SIZE {
                panic!("x509: wrong Ed25519 public key size");
            }

            PublicKey::ED25519PublicKey(ed25519::PublicKey(der.0))
        },
        val if val==OID_PUBLIC_KEY_X25519.as_slice() => {
            //
            PublicKey::X25519PublicKey
        },
        val if val==OID_PUBLIC_KEY_DSA.as_slice() => {
            //
            PublicKey::DsaPublicKey
        },
        _ => panic!("x509: unknown public key algorithm"),
    }
}

pub fn check_certs(current_time: i64, check_sum: &[u8], certs_chain: &[u8], signature: &[u8], root_cert: &[u8]) -> bool {
    // extract
    // divide input string into three slices
    println!("check_certs certs_chain is : {:?}", &certs_chain);

    let len_of_certs_chain = (certs_chain[0] as usize)*65536 + (certs_chain[1] as usize)*256 + (certs_chain[2] as usize);
    println!("check_certs len_of_certs_chain is : {:?}", len_of_certs_chain);
    println!("check_certs certs_chain.len() is : {:?}", certs_chain.len());

    if len_of_certs_chain+1 != certs_chain.len() {
        return false;
    }

    let len_of_leaf_cert = (certs_chain[3] as usize)*65536 + (certs_chain[4] as usize)*256 + (certs_chain[5] as usize);
    println!("check_certs len_of_leaf_cert is : {:?}", len_of_leaf_cert);

    let leaf_cert_slice = &certs_chain[6..len_of_leaf_cert+6];
    println!("check_certs leaf_cert_slice is : {:?}", leaf_cert_slice);

    let leaf_cert = parse_certificate(leaf_cert_slice); // leafCert, err := x509.ParseCertificate(leafCertSlice)
    //if leaf_cert.not_after.Before(time.Now()) || leaf_cert.not_before.After(time.Now()) {
        //false
    //}


    let start_index = len_of_leaf_cert + 8;
    let len_of_internal_cert = (certs_chain[start_index] as usize)*65536 + (certs_chain[start_index+1] as usize)*256 + (certs_chain[start_index+2] as usize);
    println!("check_certs len_of_internal_cert is : {:?}", len_of_internal_cert);

    let internal_cert_slice = &certs_chain[start_index + 3..start_index + len_of_internal_cert + 3];
    println!("check_certs internal_cert_slice is : {:?}", internal_cert_slice);

    let internal_cert = parse_certificate(internal_cert_slice); // internalCert, err := x509.ParseCertificate(internalCertSlice)

    println!("check_certs internal_cert.serial_number is : {:?}", internal_cert.serial_number.to_string());

    //if err != nil {
        //fmt.Printf("ParseCertificate (internalCertSlice) err is : %v\n", err.Error())
        //false
    //}

    //if internalCert.NotAfter.Before(time.Now()) || internalCert.NotBefore.After(time.Now()) {
        //return false
    //}
    let start_index = start_index + 3 + len_of_internal_cert + 2;

    let len_of_root_cert = (certs_chain[start_index] as usize)*65536 + (certs_chain[start_index+1] as usize)*256 + (certs_chain[start_index+2] as usize);
    println!("check_certs len_of_root_cert is : {:?}", len_of_root_cert);
    let root_cert_slice = &certs_chain[start_index + 3..start_index + len_of_root_cert+3];
    println!("check_certs root_cert_slice is : {:?}", root_cert_slice);

    let root_cert = parse_certificate(root_cert_slice);
    //rootCert, err := x509.ParseCertificate(rootCertSlice)
    // if err != nil {
    // fmt.Printf("ParseCertificate (rootCertSlice) err is : %v\n", err.Error())
    // return false
    // }

    //err = leafCert.CheckSignatureFrom(internalCert);
    // if err!= nil {
    // fmt.Printf("ParseCertificate CheckSignatureFrom internalCert err is : %v\n", err.Error())
    // return false
    // }

    // err = internalCert.CheckSignatureFrom(rootCert)
    //   if err!= nil {
    //     fmt.Printf("ParseCertificate CheckSignatureFrom rootCert err is : %v\n", err.Error())
    //     return false
    //   }

    match  leaf_cert.public_key_algorithm.to_string() {
        val if val=="RSA".to_string() => {
            //
            // pubkey, ok := leafCert.PublicKey.(*rsa.PublicKey)
            if let PublicKey::RsaPublicKey(pub_key) = leaf_cert.public_key {
                //
                if !rsa::verify_pkcs1v15(&pub_key,256, check_sum, signature) {
                    return false;
                }
            } else {
                return false; //ErrCertificateTypeMismatch
            }

        },
        val if val == "ECDSA".to_string() => {
            //
            if let PublicKey::ECDSAPublicKey(pub_key) = leaf_cert.public_key {
                //
                let len_of_r = signature[3] as usize;//     lenOfr := signature[3]
                //println!("len_of_r is : {:?}", len_of_r);
                let r_data = &signature[4..4+len_of_r];//     rData := signature[4:4+lenOfr]
                let len_of_s = signature[4 + len_of_r + 1] as usize;
                //println!("len_of_s is : {:?}", len_of_s);
                let s_data = &signature[4 + len_of_r + 2..4 + len_of_r + 2 + len_of_s];
                let r = BigInt::from_bytes_be(Sign::Plus, r_data); //     r := new(big.Int).SetBytes(rData)
                let s = BigInt::from_bytes_be(Sign::Plus, s_data); //     s := new(big.Int).SetBytes(sData)
                if !ecdsa::verify(&pub_key, check_sum, &r, &s) {
                    return false;
                }

            } else {
                return false;  //ErrCertificateTypeMismatch
            }

        },
        _ => panic!("Unknown signature algorithm"),
    }


    return true;
}

/*
#[test]
fn test_parsing_leaf_cert(){

    // lenOfRootCert is : 1507
    let cert_bytes = [48, 130, 5, 223, 48, 130, 4, 199, 160, 3, 2, 1, 2, 2, 16, 29, 52, 231, 130, 196, 125, 97, 31, 9, 217, 200, 245, 205,
        198, 186, 21, 48, 13, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 11, 5, 0, 48, 59, 49, 11, 48, 9, 6, 3, 85, 4, 6, 19, 2, 85, 83, 49, 30, 48,
        28, 6, 3, 85, 4, 10, 19, 21, 71, 111, 111, 103, 108, 101, 32, 84, 114, 117, 115, 116, 32, 83, 101, 114, 118, 105, 99, 101, 115, 49, 12,
        48, 10, 6, 3, 85, 4, 3, 19, 3, 87, 82, 50, 48, 30, 23, 13, 50, 53, 48, 54, 48, 50, 48, 56, 51, 54, 51, 55, 90, 23, 13, 50, 53, 48, 56, 50,
        53, 48, 56, 51, 54, 51, 54, 90, 48, 34, 49, 32, 48, 30, 6, 3, 85, 4, 3, 19, 23, 117, 112, 108, 111, 97, 100, 46, 118, 105, 100, 101, 111,
        46, 103, 111, 111, 103, 108, 101, 46, 99, 111, 109, 48, 89, 48, 19, 6, 7, 42, 134, 72, 206, 61, 2, 1, 6, 8, 42, 134, 72, 206, 61, 3, 1, 7,
        3, 66, 0, 4, 248, 83, 162, 122, 174, 15, 224, 170, 61, 240, 158, 237, 156, 11, 182, 110, 127, 239, 209, 74, 120, 97, 236, 65, 243, 24, 27,
        36, 129, 74, 199, 81, 187, 0, 174, 91, 146, 116, 246, 216, 103, 159, 198, 205, 143, 254, 100, 152, 123, 224, 77, 174, 122, 94, 243, 213,
        158, 167, 195, 80, 59, 62, 51, 87, 163, 130, 3, 193, 48, 130, 3, 189, 48, 14, 6, 3, 85, 29, 15, 1, 1, 255, 4, 4, 3, 2, 7, 128, 48, 19, 6,
        3, 85, 29, 37, 4, 12, 48, 10, 6, 8, 43, 6, 1, 5, 5, 7, 3, 1, 48, 12, 6, 3, 85, 29, 19, 1, 1, 255, 4, 2, 48, 0, 48, 29, 6, 3, 85, 29, 14,
        4, 22, 4, 20, 116, 64, 113, 233, 144, 151, 116, 8, 12, 37, 102, 162, 200, 138, 133, 220, 67, 196, 64, 182, 48, 31, 6, 3, 85, 29, 35, 4,
        24, 48, 22, 128, 20, 222, 27, 30, 237, 121, 21, 212, 62, 55, 36, 195, 33, 187, 236, 52, 57, 109, 66, 178, 48, 48, 88, 6, 8, 43, 6, 1, 5,
        5, 7, 1, 1, 4, 76, 48, 74, 48, 33, 6, 8, 43, 6, 1, 5, 5, 7, 48, 1, 134, 21, 104, 116, 116, 112, 58, 47, 47, 111, 46, 112, 107, 105, 46,
        103, 111, 111, 103, 47, 119, 114, 50, 48, 37, 6, 8, 43, 6, 1, 5, 5, 7, 48, 2, 134, 25, 104, 116, 116, 112, 58, 47, 47, 105, 46, 112, 107,
        105, 46, 103, 111, 111, 103, 47, 119, 114, 50, 46, 99, 114, 116, 48, 130, 1, 152, 6, 3, 85, 29, 17, 4, 130, 1, 143, 48, 130, 1, 139, 130,
        23, 117, 112, 108, 111, 97, 100, 46, 118, 105, 100, 101, 111, 46, 103, 111, 111, 103, 108, 101, 46, 99, 111, 109, 130, 20, 42, 46, 99, 108,
        105, 101, 110, 116, 115, 46, 103, 111, 111, 103, 108, 101, 46, 99, 111, 109, 130, 17, 42, 46, 100, 111, 99, 115, 46, 103, 111, 111, 103,
        108, 101, 46, 99, 111, 109, 130, 18, 42, 46, 100, 114, 105, 118, 101, 46, 103, 111, 111, 103, 108, 101, 46, 99, 111, 109, 130, 19, 42, 46,
        103, 100, 97, 116, 97, 46, 121, 111, 117, 116, 117, 98, 101, 46, 99, 111, 109, 130, 16, 42, 46, 103, 111, 111, 103, 108, 101, 97, 112, 105,
        115, 46, 99, 111, 109, 130, 19, 42, 46, 112, 104, 111, 116, 111, 115, 46, 103, 111, 111, 103, 108, 101, 46, 99, 111, 109, 130, 23, 42, 46,
        121, 111, 117, 116, 117, 98, 101, 45, 51, 114, 100, 45, 112, 97, 114, 116, 121, 46, 99, 111, 109, 130, 17, 117, 112, 108, 111, 97, 100, 46, 103, 111, 111, 103, 108, 101, 46, 99, 111, 109, 130, 19, 42, 46, 117, 112, 108, 111, 97, 100, 46, 103, 111, 111, 103, 108, 101, 46, 99, 111, 109, 130, 18, 117, 112, 108, 111, 97, 100, 46, 121, 111, 117, 116, 117, 98, 101, 46, 99, 111, 109, 130, 20, 42, 46, 117, 112, 108, 111, 97, 100, 46, 121, 111, 117, 116, 117, 98, 101, 46, 99, 111, 109, 130, 31, 117, 112, 108, 111, 97, 100, 115, 46, 115, 116, 97, 103, 101, 46, 103, 100, 97, 116, 97, 46, 121, 111, 117, 116, 117, 98, 101, 46, 99, 111, 109, 130, 21, 98, 103, 45, 99, 97, 108, 108, 45, 100, 111, 110, 97, 116, 105, 111, 110, 46, 103, 111, 111, 103, 130, 27, 98, 103, 45, 99, 97, 108, 108, 45, 100, 111, 110, 97, 116, 105, 111, 110, 45, 97, 108, 112, 104, 97, 46, 103, 111, 111, 103, 130, 28, 98, 103, 45, 99, 97, 108, 108, 45, 100, 111, 110, 97, 116, 105, 111, 110, 45, 99, 97, 110, 97, 114, 121, 46, 103, 111, 111, 103, 130, 25, 98, 103, 45, 99, 97, 108, 108, 45, 100, 111, 110, 97, 116, 105, 111, 110, 45, 100, 101, 118, 46, 103, 111, 111, 103, 48, 19, 6, 3, 85, 29, 32, 4, 12, 48, 10, 48, 8, 6, 6, 103, 129, 12, 1, 2, 1, 48, 54, 6, 3, 85, 29, 31, 4, 47, 48, 45, 48, 43, 160, 41, 160, 39, 134, 37, 104, 116, 116, 112, 58, 47, 47, 99, 46, 112, 107, 105, 46, 103, 111, 111, 103, 47, 119, 114, 50, 47, 71, 83, 121, 84, 49, 78, 52, 80, 66, 114, 103, 46, 99, 114, 108, 48, 130, 1, 3, 6, 10, 43, 6, 1, 4, 1, 214, 121, 2, 4, 2, 4, 129, 244, 4, 129, 241, 0, 239, 0, 118, 0, 221, 220, 202, 52, 149, 215, 225, 22, 5, 231, 149, 50, 250, 199, 159, 248, 61, 28, 80, 223, 219, 0, 58, 20, 18, 118, 10, 44, 172, 187, 200, 42, 0, 0, 1, 151, 48, 0, 13, 18, 0, 0, 4, 3, 0, 71, 48, 69, 2, 32, 25, 141, 105, 240, 199, 112, 242, 232, 208, 105, 216, 166, 198, 180, 16, 170, 174, 162, 33, 83, 140, 69, 155, 81, 15, 88, 241, 55, 220, 71, 137, 236, 2, 33, 0, 147, 92, 188, 175, 12, 195, 251, 3, 208, 216, 50, 217, 185, 244, 35, 53, 6, 13, 224, 137, 152, 132, 209, 23, 99, 2, 209, 204, 104, 39, 35, 72, 0, 117, 0, 125, 89, 30, 18, 225, 120, 42, 123, 28, 97, 103, 124, 94, 253, 248, 208, 135, 92, 20, 160, 78, 149, 158, 185, 3, 47, 217, 14, 140, 46, 121, 184, 0, 0, 1, 151, 48, 0, 16, 208, 0, 0, 4, 3, 0, 70, 48, 68, 2, 32, 86, 158, 142, 171, 240, 161, 218, 234, 10, 163, 215, 135, 65, 120, 205, 47, 143, 227, 51, 230, 77, 112, 48, 136, 100, 237, 136, 188, 205, 109, 90, 253, 2, 32, 64, 92, 213, 9, 82, 102, 85, 218, 69, 87, 96, 98, 122, 235, 105, 165, 218, 55, 81, 91, 232, 94, 251, 46, 21, 135, 147, 229, 162, 244, 208, 58, 48, 13, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 11, 5, 0, 3, 130, 1, 1, 0, 78, 0, 2, 76, 206, 91, 50, 221, 129, 45, 231, 23, 12, 75, 193, 40, 29, 199, 204, 67, 202, 92, 143, 89, 184, 88, 188, 239, 123, 103, 60, 53, 75, 157, 164, 31, 47, 122, 150, 158, 92, 128, 110, 61, 15, 220, 150, 132, 113, 219, 92, 116, 154, 234, 58, 38, 210, 108, 74, 177, 255, 177, 152, 61, 36, 192, 169, 80, 82, 91, 174, 92, 201, 41, 89, 43, 103, 144, 144, 141, 191, 186, 29, 253, 77, 180, 173, 116, 43, 88, 139, 127, 214, 211, 240, 132, 208, 45, 252, 194, 174, 69, 3, 83, 195, 72, 47, 229, 107, 147, 192, 243, 235, 38, 50, 49, 111, 223, 217, 56, 39, 245, 192, 31, 88, 16, 138, 91, 44, 252, 121, 222, 6, 179, 251, 251, 214, 111, 49, 175, 194, 228, 200, 23, 9, 38, 95, 236, 34, 197, 88, 45, 64, 131, 118, 113, 226, 28, 131, 166, 230, 217, 43, 255, 107, 115, 114, 16, 82, 65, 121, 193, 19, 2, 155, 87, 24, 247, 182, 59, 114, 227, 162, 2, 132, 33, 187, 102, 100, 232, 115, 252, 113, 200, 214, 124, 228, 193, 234, 91, 243, 88, 161, 61, 122, 11, 148, 173, 161, 5, 175, 21, 238, 25, 239, 41, 152, 162, 7, 9, 184, 180, 18, 16, 182, 105, 24, 130, 170, 97, 140, 247, 142, 68, 65, 138, 182, 235, 17, 241, 151, 219, 137, 204, 70, 183, 131, 65, 70, 186, 107, 234, 22, 172, 179, 255];
    let certificate = parse_certificate(&cert_bytes);

    println!("the certificate.version is : {:?}", &certificate.version);
    println!("the certificate.serial_number is : {:?}", &certificate.serial_number);

    let certificate_version: i64 = 2;
    assert_eq!(certificate.version, certificate_version);

    let cert_serial_number = BigInt::from(38822306911496578035668995664819698197);
    assert_eq!(certificate.serial_number, cert_serial_number);
}

#[test]
fn test_parsing_internal_cert(){
    // len is 1295
    let cert_bytes = [48, 130, 5, 11, 48, 130, 2, 243, 160, 3, 2, 1, 2, 2, 16, 127, 240, 5, 160, 124, 76, 222, 209, 0, 173, 157, 102, 165,
        16, 123, 152, 48, 13, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 11, 5, 0, 48, 71, 49, 11, 48, 9, 6, 3, 85, 4, 6, 19, 2, 85, 83, 49, 34, 48, 32,
        6, 3, 85, 4, 10, 19, 25, 71, 111, 111, 103, 108, 101, 32, 84, 114, 117, 115, 116, 32, 83, 101, 114, 118, 105, 99, 101, 115, 32, 76, 76, 67,
        49, 20, 48, 18, 6, 3, 85, 4, 3, 19, 11, 71, 84, 83, 32, 82, 111, 111, 116, 32, 82, 49, 48, 30, 23, 13, 50, 51, 49, 50, 49, 51, 48, 57, 48, 48, 48, 48, 90, 23, 13, 50, 57, 48, 50, 50, 48, 49, 52, 48, 48, 48, 48, 90, 48, 59, 49, 11, 48, 9, 6, 3, 85, 4, 6, 19, 2, 85, 83, 49, 30, 48, 28, 6, 3, 85, 4, 10, 19, 21, 71, 111, 111, 103, 108, 101, 32, 84, 114, 117, 115, 116, 32, 83, 101, 114, 118, 105, 99, 101, 115, 49, 12, 48, 10, 6, 3, 85, 4, 3, 19, 3, 87, 82, 50, 48, 130, 1, 34, 48, 13, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 1, 5, 0, 3, 130, 1, 15, 0, 48, 130, 1, 10, 2, 130, 1, 1, 0, 169, 255, 156, 127, 69, 30, 112, 168, 83, 159, 202, 217, 229, 13, 222, 70, 87, 87, 125, 188, 143, 154, 90, 172, 70, 241, 132, 154, 187, 145, 219, 201, 251, 47, 1, 251, 146, 9, 0, 22, 94, 160, 28, 248, 193, 171, 249, 120, 47, 74, 204, 216, 133, 162, 216, 89, 60, 14, 211, 24, 251, 177, 245, 36, 13, 38, 238, 182, 91, 100, 118, 124, 20, 199, 47, 122, 206, 168, 76, 183, 244, 217, 8, 252, 223, 135, 35, 53, 32, 168, 226, 105, 226, 140, 78, 63, 177, 89, 250, 96, 162, 30, 179, 201, 32, 83, 25, 130, 202, 54, 83, 109, 96, 77, 233, 0, 145, 252, 118, 141, 92, 8, 15, 10, 194, 220, 241, 115, 107, 197, 19, 110, 10, 79, 122, 194, 242, 2, 28, 46, 180, 99, 131, 218, 49, 246, 45, 117, 48, 178, 251, 171, 194, 110, 219, 169, 192, 14, 185, 249, 103, 212, 195, 37, 87, 116, 235, 5, 180, 233, 142, 181, 222, 40, 205, 204, 122, 20, 228, 113, 3, 203, 77, 97, 46, 97, 87, 197, 25, 169, 11, 152, 132, 26, 232, 121, 41, 217, 178, 141, 47, 255, 87, 106, 102, 224, 206, 171, 149, 168, 41, 150, 99, 112, 18, 103, 30, 58, 225, 219, 176, 33, 113, 215, 124, 158, 253, 170, 23, 110, 254, 43, 251, 56, 23, 20, 209, 102, 167, 175, 154, 181, 112, 204, 200, 99, 129, 58, 140, 192, 42, 169, 118, 55, 206, 227, 2, 3, 1, 0, 1, 163, 129, 254, 48, 129, 251, 48, 14, 6, 3, 85, 29, 15, 1, 1, 255, 4, 4, 3, 2, 1, 134, 48, 29, 6, 3, 85, 29, 37, 4, 22, 48, 20, 6, 8, 43, 6, 1, 5, 5, 7, 3, 1, 6, 8, 43, 6, 1, 5, 5, 7, 3, 2, 48, 18, 6, 3, 85, 29, 19, 1, 1, 255, 4, 8, 48, 6, 1, 1, 255, 2, 1, 0, 48, 29, 6, 3, 85, 29, 14, 4, 22, 4, 20, 222, 27, 30, 237, 121, 21, 212, 62, 55, 36, 195, 33, 187, 236, 52, 57, 109, 66, 178, 48, 48, 31, 6, 3, 85, 29, 35, 4, 24, 48, 22, 128, 20, 228, 175, 43, 38, 113, 26, 43, 72, 39, 133, 47, 82, 102, 44, 239, 240, 137, 19, 113, 62, 48, 52, 6, 8, 43, 6, 1, 5, 5, 7, 1, 1, 4, 40, 48, 38, 48, 36, 6, 8, 43, 6, 1, 5, 5, 7, 48, 2, 134, 24, 104, 116, 116, 112, 58, 47, 47, 105, 46, 112, 107, 105, 46, 103, 111, 111, 103, 47, 114, 49, 46, 99, 114, 116, 48, 43, 6, 3, 85, 29, 31, 4, 36, 48, 34, 48, 32, 160, 30, 160, 28, 134, 26, 104, 116, 116, 112, 58, 47, 47, 99, 46, 112, 107, 105, 46, 103, 111, 111, 103, 47, 114, 47, 114, 49, 46, 99, 114, 108, 48, 19, 6, 3, 85, 29, 32, 4, 12, 48, 10, 48, 8, 6, 6, 103, 129, 12, 1, 2, 1, 48, 13, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 11, 5, 0, 3, 130, 2, 1, 0, 69, 117, 139, 229, 31, 59, 68, 19, 150, 26, 171, 88, 241, 53, 201, 111, 61, 210, 208, 51, 74, 134, 51, 186, 87, 81, 79, 238, 196, 52, 218, 22, 18, 76, 191, 19, 159, 13, 212, 84, 233, 72, 121, 192, 48, 60, 148, 37, 242, 26, 244, 186, 50, 148, 182, 51, 114, 11, 133, 238, 9, 17, 37, 52, 148, 225, 111, 66, 219, 130, 155, 123, 127, 42, 154, 169, 255, 127, 169, 210, 222, 74, 32, 203, 179, 251, 3, 3, 184, 248, 7, 5, 218, 89, 146, 47, 24, 70, 152, 206, 175, 114, 190, 36, 38, 177, 30, 0, 77, 189, 8, 173, 147, 65, 68, 10, 187, 199, 213, 1, 133, 191, 147, 87, 227, 223, 116, 18, 83, 14, 17, 37, 211, 155, 220, 222, 203, 39, 110, 179, 194, 185, 51, 98, 57, 194, 224, 53, 225, 91, 167, 9, 46, 25, 203, 145, 42, 118, 92, 241, 223, 202, 35, 132, 64, 165, 111, 255, 154, 65, 224, 181, 239, 50, 209, 133, 174, 175, 37, 9, 240, 98, 197, 110, 194, 200, 110, 50, 253, 184, 218, 226, 206, 74, 145, 74, 243, 133, 85, 78, 177, 117, 214, 72, 51, 47, 111, 132, 217, 18, 92, 159, 212, 113, 152, 99, 37, 141, 105, 92, 10, 107, 125, 242, 65, 189, 232, 187, 143, 228, 34, 215, 157, 101, 69, 232, 76, 10, 135, 218, 233, 96, 102, 136, 14, 31, 199, 225, 78, 86, 197, 118, 255, 180, 122, 87, 105, 242, 2, 34, 9, 38, 65, 29, 218, 116, 162, 229, 41, 243, 196, 154, 229, 93, 214, 170, 122, 253, 225, 183, 43, 102, 56, 251, 232, 41, 102, 186, 239, 160, 19, 47, 248, 115, 126, 240, 218, 64, 17, 28, 93, 221, 143, 166, 252, 190, 219, 190, 86, 248, 50, 156, 31, 65, 65, 109, 126, 182, 197, 235, 198, 139, 54, 183, 23, 140, 157, 207, 25, 122, 52, 159, 33, 147, 196, 126, 116, 53, 210, 170, 253, 76, 109, 20, 245, 201, 176, 121, 91, 73, 60, 243, 191, 23, 72, 232, 239, 154, 38, 19, 12, 135, 242, 115, 214, 156, 197, 82, 107, 99, 247, 50, 144, 120, 169, 107, 235, 94, 214, 147, 161, 191, 188, 24, 61, 139, 89, 246, 138, 198, 5, 94, 82, 24, 226, 102, 224, 218, 193, 220, 173, 90, 37, 170, 244, 69, 252, 241, 11, 120, 164, 175, 176, 242, 115, 164, 48, 168, 52, 193, 83, 127, 66, 150, 229, 72, 65, 235, 144, 70, 12, 6, 220, 203, 146, 198, 94, 243, 68, 68, 67, 70, 41, 70, 160, 166, 252, 185, 142, 57, 39, 57, 177, 90, 226, 177, 173, 252, 19, 255, 142, 252, 38, 225, 212, 254, 132, 241, 80, 90, 142, 151, 107, 45, 42, 121, 251, 64, 100, 234, 243, 61, 189, 91, 225, 160, 4, 176, 151, 72, 28, 66, 245, 234, 90, 28, 205, 38, 200, 81, 255, 20, 153, 103, 137, 114, 95, 29, 236, 173, 90, 221];
    let certificate = parse_certificate(&cert_bytes);

    println!("the certificate.version is : {:?}", &certificate.version);
    println!("the certificate.serial_number is : {:?}", &certificate.serial_number);

    // lenOfRootCert is : 1382
    let certificate_version: i64 = 2;
    assert_eq!(certificate.version, certificate_version);
    let cert_serial_number = BigInt(170058220837755766831192027518741805976);
    assert_eq!(certificate.serial_number, cert_serial_number);
}*/


#[test]
fn test_parsing_root_cert_from_inet(){

    let cert_bytes = [48, 130, 5, 98, 48, 130, 4, 74, 160, 3, 2, 1, 2, 2, 16, 119, 189, 13, 108, 219, 54, 249, 26, 234, 33, 15, 196, 240,
        88, 211, 13, 48, 13, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 11, 5, 0, 48, 87, 49, 11, 48, 9, 6, 3, 85, 4, 6, 19, 2, 66, 69, 49, 25, 48, 23,
        6, 3, 85, 4, 10, 19, 16, 71, 108, 111, 98, 97, 108, 83, 105, 103, 110, 32, 110, 118, 45, 115, 97, 49, 16, 48, 14, 6, 3, 85, 4, 11, 19, 7,
        82, 111, 111, 116, 32, 67, 65, 49, 27, 48, 25, 6, 3, 85, 4, 3, 19, 18, 71, 108, 111, 98, 97, 108, 83, 105, 103, 110, 32, 82, 111, 111, 116,
        32, 67, 65, 48, 30, 23, 13, 50, 48, 48, 54, 49, 57, 48, 48, 48, 48, 52, 50, 90, 23, 13, 50, 56, 48, 49, 50, 56, 48, 48, 48, 48, 52, 50, 90,
        48, 71, 49, 11, 48, 9, 6, 3, 85, 4, 6, 19, 2, 85, 83, 49, 34, 48, 32, 6, 3, 85, 4, 10, 19, 25, 71, 111, 111, 103, 108, 101, 32, 84, 114,
        117, 115, 116, 32, 83, 101, 114, 118, 105, 99, 101, 115, 32, 76, 76, 67, 49, 20, 48, 18, 6, 3, 85, 4, 3, 19, 11, 71, 84, 83, 32, 82, 111,
        111, 116, 32, 82, 49, 48, 130, 2, 34, 48, 13, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 1, 5, 0, 3, 130, 2, 15, 0, 48, 130, 2, 10, 2, 130, 2,
        1, 0, 182, 17, 2, 139, 30, 227, 161, 119, 155, 59, 220, 191, 148, 62, 183, 149, 167, 64, 60, 161, 253, 130, 249, 125, 50, 6, 130, 113, 246,
        246, 140, 127, 251, 232, 219, 188, 106, 46, 151, 151, 163, 140, 75, 249, 43, 246, 177, 249, 206, 132, 29, 177, 249, 197, 151, 222, 239, 185,
        242, 163, 233, 188, 18, 137, 94, 167, 170, 82, 171, 248, 35, 39, 203, 164, 177, 156, 99, 219, 215, 153, 126, 240, 10, 94, 235, 104, 166, 244,
        198, 90, 71, 13, 77, 16, 51, 227, 78, 177, 19, 163, 200, 24, 108, 75, 236, 252, 9, 144, 223, 157, 100, 41, 37, 35, 7, 161, 180, 210, 61, 46,
        96, 224, 207, 210, 9, 135, 187, 205, 72, 240, 77, 194, 194, 122, 136, 138, 187, 186, 207, 89, 25, 214, 175, 143, 176, 7, 176, 158, 49, 241,
        130, 193, 192, 223, 46, 166, 109, 108, 25, 14, 181, 216, 126, 38, 26, 69, 3, 61, 176, 121, 164, 148, 40, 173, 15, 127, 38, 229, 168, 8, 254,
        150, 232, 60, 104, 148, 83, 238, 131, 58, 136, 43, 21, 150, 9, 178, 224, 122, 140, 46, 117, 214, 156, 235, 167, 86, 100, 143, 150, 79, 104,
        174, 61, 151, 194, 132, 143, 192, 188, 64, 192, 11, 92, 189, 246, 135, 179, 53, 108, 172, 24, 80, 127, 132, 224, 76, 205, 146, 211, 32, 233,
        51, 188, 82, 153, 175, 50, 181, 41, 179, 37, 42, 180, 72, 249, 114, 225, 202, 100, 247, 230, 130, 16, 141, 232, 157, 194, 138, 136, 250, 56,
        102, 138, 252, 99, 249, 1, 249, 120, 253, 123, 92, 119, 250, 118, 135, 250, 236, 223, 177, 14, 121, 149, 87, 180, 189, 38, 239, 214, 1, 209,
        235, 22, 10, 187, 142, 11, 181, 197, 197, 138, 85, 171, 211, 172, 234, 145, 75, 41, 204, 25, 164, 50, 37, 78, 42, 241, 101, 68, 208, 2, 206,
        170, 206, 73, 180, 234, 159, 124, 131, 176, 64, 123, 231, 67, 171, 167, 108, 163, 143, 125, 137, 129, 250, 76, 165, 255, 213, 142, 195, 206,
        75, 224, 181, 216, 179, 142, 69, 207, 118, 192, 237, 64, 43, 253, 83, 15, 176, 167, 213, 59, 13, 177, 138, 162, 3, 222, 49, 173, 204, 119,
        234, 111, 123, 62, 214, 223, 145, 34, 18, 230, 190, 250, 216, 50, 252, 16, 99, 20, 81, 114, 222, 93, 214, 22, 147, 189, 41, 104, 51, 239,
        58, 102, 236, 7, 138, 38, 223, 19, 215, 87, 101, 120, 39, 222, 94, 73, 20, 0, 162, 0, 127, 154, 168, 33, 182, 169, 177, 149, 176, 165, 185,
        13, 22, 17, 218, 199, 108, 72, 60, 64, 224, 126, 13, 90, 205, 86, 60, 209, 151, 5, 185, 203, 75, 237, 57, 75, 156, 196, 63, 210, 85, 19,
        110, 36, 176, 214, 113, 250, 244, 193, 186, 204, 237, 27, 245, 254, 129, 65, 216, 0, 152, 61, 58, 200, 174, 122, 152, 55, 24, 5, 149, 2,
        3, 1, 0, 1, 163, 130, 1, 56, 48, 130, 1, 52, 48, 14, 6, 3, 85, 29, 15, 1, 1, 255, 4, 4, 3, 2, 1, 134, 48, 15, 6, 3, 85, 29, 19, 1, 1, 255,
        4, 5, 48, 3, 1, 1, 255, 48, 29, 6, 3, 85, 29, 14, 4, 22, 4, 20, 228, 175, 43, 38, 113, 26, 43, 72, 39, 133, 47, 82, 102, 44, 239, 240, 137,
        19, 113, 62, 48, 31, 6, 3, 85, 29, 35, 4, 24, 48, 22, 128, 20, 96, 123, 102, 26, 69, 13, 151, 202, 137, 80, 47, 125, 4, 205, 52, 168, 255,
        252, 253, 75, 48, 96, 6, 8, 43, 6, 1, 5, 5, 7, 1, 1, 4, 84, 48, 82, 48, 37, 6, 8, 43, 6, 1, 5, 5, 7, 48, 1, 134, 25, 104, 116, 116, 112,
        58, 47, 47, 111, 99, 115, 112, 46, 112, 107, 105, 46, 103, 111, 111, 103, 47, 103, 115, 114, 49, 48, 41, 6, 8, 43, 6, 1, 5, 5, 7, 48, 2,
        134, 29, 104, 116, 116, 112, 58, 47, 47, 112, 107, 105, 46, 103, 111, 111, 103, 47, 103, 115, 114, 49, 47, 103, 115, 114, 49, 46, 99, 114,
        116, 48, 50, 6, 3, 85, 29, 31, 4, 43, 48, 41, 48, 39, 160, 37, 160, 35, 134, 33, 104, 116, 116, 112, 58, 47, 47, 99, 114, 108, 46, 112,
        107, 105, 46, 103, 111, 111, 103, 47, 103, 115, 114, 49, 47, 103, 115, 114, 49, 46, 99, 114, 108, 48, 59, 6, 3, 85, 29, 32, 4, 52, 48, 50,
        48, 8, 6, 6, 103, 129, 12, 1, 2, 1, 48, 8, 6, 6, 103, 129, 12, 1, 2, 2, 48, 13, 6, 11, 43, 6, 1, 4, 1, 214, 121, 2, 5, 3, 2, 48, 13, 6, 11,
        43, 6, 1, 4, 1, 214, 121, 2, 5, 3, 3, 48, 13, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 11, 5, 0, 3, 130, 1, 1, 0, 52, 164, 30, 177, 40, 163,
        208, 180, 118, 23, 166, 49, 122, 33, 233, 209, 82, 62, 200, 219, 116, 22, 65, 136, 184, 61, 53, 29, 237, 228, 255, 147, 225, 92, 95, 171,
        187, 234, 124, 207, 219, 228, 13, 209, 139, 87, 242, 38, 111, 91, 190, 23, 70, 104, 148, 55, 111, 107, 122, 200, 192, 24, 55, 250, 37, 81,
        172, 236, 104, 191, 178, 200, 73, 253, 90, 154, 202, 1, 35, 172, 132, 128, 43, 2, 140, 153, 151, 235, 73, 106, 140, 117, 215, 199, 222,
        178, 201, 151, 159, 88, 72, 87, 14, 53, 161, 228, 26, 214, 253, 111, 131, 129, 111, 239, 140, 207, 151, 175, 192, 133, 42, 240, 245, 78,
        105, 9, 145, 45, 225, 104, 184, 193, 43, 115, 233, 212, 217, 252, 34, 192, 55, 31, 11, 102, 29, 73, 237, 2, 85, 143, 103, 225, 50, 215,
        211, 38, 191, 112, 227, 61, 244, 103, 109, 61, 124, 229, 52, 136, 227, 50, 250, 167, 110, 6, 106, 111, 189, 139, 145, 238, 22, 75, 232,
        59, 169, 179, 55, 231, 195, 68, 164, 126, 216, 108, 215, 199, 70, 245, 146, 155, 231, 213, 33, 190, 102, 146, 25, 148, 85, 108, 212, 41,
        178, 13, 193, 102, 91, 226, 119, 73, 72, 40, 237, 157, 215, 26, 51, 114, 83, 179, 130, 53, 207, 98, 139, 201, 36, 139, 165, 183, 57, 12,
        187, 126, 42, 65, 191, 82, 207, 252, 162, 150, 182, 194, 130, 63];
    let certificate = parse_certificate(&cert_bytes);

    println!("the certificate.version is : {:?}", &certificate.version);
    println!("the certificate.serial_number is : {:?}", &certificate.serial_number.to_string());
    println!("the certificate.issuer.names is : {:?}", &certificate.issuer.names);
    println!("the certificate.public_key is : {:?}", &certificate.public_key);

    // lenOfRootCert is : 1382
    let certificate_version: i64 = 3;
    assert_eq!(certificate.version, certificate_version);
    let cert_serial_number = BigInt::from_str("159159747900478145820483398898491642637").unwrap();
    assert_eq!(certificate.serial_number, cert_serial_number);
    //let cert_issuer = Name{}; // CN=GlobalSign Root CA,OU=Root CA,O=GlobalSign nv-sa,C=BE
    //certificate.issuer = CN=GlobalSign Root CA,OU=Root CA,O=GlobalSign nv-sa,C=BE

    assert_eq!(certificate.public_key_algorithm, PublicKeyAlgorithm::RSA); //rootCert.PublicKeyAlgorithm is : RSA
    // rootCert.PublicKey is : &{742766292573789461138430713106656498577482106105452767343211753017973550878861638590047246174848574634573720584492944669558785810905825702100325794803983120697401526210439826606874730300903862093323398754125584892080731234772626570955922576399434033022944334623029747454371697865218999618129768679013891932765999545116374192173968985738129135224425889467654431372779943313524100225335793262665132039441111162352797240438393795570253671786791600672076401253164614309929080014895216439462173458352253266568535919120175826866378039177020829725517356783703110010084715777806343235841345264684364598708732655710904078855499605447884872767583987312177520332134164321746982952420498393591583416464199126272682424674947720461866762624768163777784559646117979893432692133818266724658906066075396922419161138847526583266030290937955148683298741803605463007526904924936746018546134099068479370078440023459839544052468222048449819089106832452146002755336956394669648596035188293917750838002531358091511944112847917218550963597247358780879029417872466325821996717925086546502702016501643824750668459565101211439428003662613442032518886622942136328590823063627643918273848803884791311375697313014431195473178892344923166262358299334827234064598421 65537}

    let rsa_public_n = BigInt::from_str("742766292573789461138430713106656498577482106105452767343211753017973550878861638590047246174848574634573720584492944669558785810905825702100325794803983120697401526210439826606874730300903862093323398754125584892080731234772626570955922576399434033022944334623029747454371697865218999618129768679013891932765999545116374192173968985738129135224425889467654431372779943313524100225335793262665132039441111162352797240438393795570253671786791600672076401253164614309929080014895216439462173458352253266568535919120175826866378039177020829725517356783703110010084715777806343235841345264684364598708732655710904078855499605447884872767583987312177520332134164321746982952420498393591583416464199126272682424674947720461866762624768163777784559646117979893432692133818266724658906066075396922419161138847526583266030290937955148683298741803605463007526904924936746018546134099068479370078440023459839544052468222048449819089106832452146002755336956394669648596035188293917750838002531358091511944112847917218550963597247358780879029417872466325821996717925086546502702016501643824750668459565101211439428003662613442032518886622942136328590823063627643918273848803884791311375697313014431195473178892344923166262358299334827234064598421").unwrap();
    let etalon_pk = PublicKey::RsaPublicKey(rsa::PublicKey{n: rsa_public_n, e: 65537});
    println!("etalon public_key is : {:?}", &etalon_pk);
    assert_eq!(etalon_pk, certificate.public_key);
}

//#[test]
//fn test_parsing_root_cert_from_alina(){
    //parseCertificate cert.Version is : 2
    // parseCertificate cert.SerialNumber is : 146587176229350439916519468929765261721
    // etalonRootCert.Issuer is : CN=GTS Root R4,O=Google Trust Services LLC,C=US
    // etalonRootCert.PublicKeyAlgorithm is : ECDSA
    // etalonRootCert.PublicKey is : &{0x490850 37471137007972414188180584817005857701594611622436499579709175026540926241259029249891351931980308501383755467997302 9183005163897397881300021216631269301828759039006067320487338515525388614843808427732645382476107253937965649436042}
    // etalonRootCert.Issuer is : CN=GTS Root R4,O=Google Trust Services LLC,C=US
//}