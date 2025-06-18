//use core::slice::SlicePattern;
use std::net;
use std::time::SystemTime;

// Tag represents an ASN.1 identifier octet, consisting of a tag number
// (indicating a type) and class (such as context-specific or constructed).
//
// Methods in the cryptobyte package only support the low-tag-number form, i.e.
// a single identifier octet with bits 7-8 encoding the class and bits 1-6
// encoding the tag number.
#[derive(Clone, Copy, Debug)]
pub struct Tag(u8);

const CLASS_CONSTRUCTED: u8 = 0x20;
const CLASS_CONTEXT_SPECIFIC: u8 = 0x80;

// Методы для Tag
impl Tag {

    // Установка бита контекстного специфического класса
    pub fn context_specific(self) -> Tag {
        Tag(self.0 | CLASS_CONTEXT_SPECIFIC)
    }
}

// Стандартные комбинации тегов и классов
pub const BOOLEAN: Tag = Tag(1);
pub const INTEGER: Tag = Tag(2);
pub const BIT_STRING: Tag = Tag(3);
pub const OCTET_STRING: Tag = Tag(4);
pub const NULL: Tag = Tag(5);
pub const OBJECT_IDENTIFIER: Tag = Tag(6);
pub const ENUM: Tag = Tag(10);
pub const UTF8_STRING: Tag = Tag(12);
pub const SEQUENCE: Tag = Tag(16 | CLASS_CONSTRUCTED);
pub const SET: Tag = Tag(17 | CLASS_CONSTRUCTED);
pub const PRINTABLE_STRING: Tag = Tag(19);
pub const T61_STRING: Tag = Tag(20);
pub const IA5_STRING: Tag = Tag(22);
pub const UTC_TIME: Tag = Tag(23);
pub const GENERALIZED_TIME: Tag = Tag(24);
pub const GENERAL_STRING: Tag = Tag(27);

// Предполагается, что String - это структура, которая обрабатывает данные ASN.1
#[derive(Debug, Clone)]
pub struct ASN1String(Vec<u8>); // Используется Vec<u8> для представления строки

impl ASN1String {


    pub fn read_asn1(&mut self, out: &mut ASN1String, tag: Tag) -> bool {
        let mut t = Tag(0);
        if !self.read_any_asn1(out, &mut t) || t.0 != tag.0 {
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
    pub fn read_asn1_element(&mut self, out: &mut ASN1String, tag: Tag) -> bool {
        let mut t = Tag(0);
        if !self.read_any_asn1_element(out, &mut t) || t.0 != tag.0 {
            return false;
        }
        true
    }

    // Чтение любого ASN.1
    pub fn read_any_asn1(&mut self, out: &mut ASN1String, out_tag: &mut Tag) -> bool {
        self.read_asn1_inner(out, out_tag, true)
    }

    // Чтение любого ASN.1 элемента
    // ReadAnyASN1Element reads the contents of a DER-encoded ASN.1 element
    // (including tag and length bytes) into out, sets outTag to is tag, and
    // advances. It reports whether the read was successful.
    //
    // Tags greater than 30 are not supported (i.e. low-tag-number format only).
    pub fn read_any_asn1_element(&mut self, out: &mut ASN1String, out_tag: &mut Tag) -> bool {
        self.read_asn1_inner(out, out_tag, false)
    }

    /*

    // Проверка тега ASN.1
    pub fn peek_asn1_tag(&self, tag: Tag) -> bool {
        self.0.is_empty().then(|| false).unwrap_or(Tag(self.0[0]).0 == tag.0)
    }

    // Пропуск ASN.1
    pub fn skip_asn1(&mut self, tag: Tag) -> bool {
        let mut unused = ASN1String(vec![]);
        self.read_asn1(&mut unused, tag)
    }

    // Чтение необязательного ASN.1
    pub fn read_optional_asn1(&mut self, out: &mut ASN1String, out_present: &mut bool, tag: Tag) -> bool {
        let present = self.peek_asn1_tag(tag);
        //if let Some(ref mut p) = out_present {
            // *p = present;
        //}
        //out_present = present;
        if present && !self.read_asn1(out, tag) {
            return false;
        }
        true
    }

    // Пропуск необязательного ASN.1
    pub fn skip_optional_asn1(&mut self, tag: Tag) -> bool {
        if !self.peek_asn1_tag(tag) {
            return true;
        }
        let mut unused = ASN1String(vec![]);
        self.read_asn1(&mut unused, tag)
    }

    // Чтение необязательного ASN.1 целого числа
    pub fn read_optional_asn1_integer(&mut self, out: &mut dyn std::any::Any, tag: Tag, default_value: &dyn std::any::Any) -> bool {
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
            return true;
        }

        //if !i.read_asn1_integer(out) || !i.is_empty() {
            //return false;
        //}

        true
    }


    // Чтение ASN.1 INTEGER в out
    //pub fn read_asn1_integer(&mut self, out: &mut dyn std::any::Any) -> bool {
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

    // Проверка на корректность ASN.1 INTEGER
    //pub fn check_asn1_integer(bytes: &[u8]) -> bool {
        //if bytes.is_empty() {
            // INTEGER кодируется как минимум одним октетом
            //return false;
        //}
        //if bytes.len() == 1 {
            //return true;
        //}
        //if (bytes[0] == 0 && (bytes[1] & 0x80) == 0) || (bytes[0] == 0xff && (bytes[1] & 0x80) == 0x80) {
            // Значение не минимально закодировано
            //return false;
        //}
        //true
    //}

    // Вставьте ваши реализации методов read_asn1_int64, read_asn1_uint64, read_asn1_big_int и read_asn1_bytes
    //fn read_asn1_int64(&mut self, _out: &mut i64) -> bool {
        // Тело функции для чтения ASN.1 INT64
        // Реализуйте вашу логику здесь
        //unimplemented!()
    //}

    //fn read_asn1_uint64(&mut self, _out: &mut u64) -> bool {
        // Тело функции для чтения ASN.1 UINT64
        // Реализуйте вашу логику здесь
        //unimplemented!()
    //}

    //fn read_asn1_big_int(&mut self, _out: &mut BigInt) -> bool {
        // Тело функции для чтения ASN.1 BigInt
        // Реализуйте вашу логику здесь
        //unimplemented!()
    //}

    //fn read_asn1_bytes(&mut self, _out: &mut Vec<u8>) -> bool {
        // Тело функции для чтения ASN.1 bytes
        // Реализуйте вашу логику здесь
        //unimplemented!()
    //}
    */

    pub fn read_asn1_inner(&mut self, out: &mut ASN1String, out_tag: &mut Tag, skip_header: bool) -> bool {
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
        //out_tag = Tag(tag);

        // ITU-T X.690 section 8.1.3
        let (length, header_len) = if len_byte & 0x80 == 0 {
            // Короткая длина (section 8.1.3.4), закодированная в битах 1-7.
            (u32::from(len_byte) + 2, 2)
        } else {
            // Длинная длина (section 8.1.3.5).
            let len_len = len_byte & 0x7f;

            if len_len == 0 || len_len > 4 || self.0.len() < (2 + len_len as usize) {
                return false;
            }

            let mut len_bytes = ASN1String(self.0[2..2 + len_len as usize].to_vec());
            let mut len32 = 0u32;
            if !len_bytes.read_unsigned(&mut len32, len_len as usize) {
                return false;
            }

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

        if length as usize > self.0.len() || !self.read_bytes(out, length as usize) {
            return false;
        }
        if skip_header && !out.skip(header_len as usize) {
            panic!("cryptobyte: internal error");
        }

        true
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

    fn skip(&mut self, length: usize) -> bool {
        // Реализация пропуска определенного количества байтов
        if length <= self.0.len() {
            self.0.drain(..length);
            true
        } else {
            false
        }
    }
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
    //pub id: ObjectIdentifier,
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
    //pub names: Vec<AttributeTypeAndValue>, // Все разобранные атрибуты
    //pub extra_names: Vec<AttributeTypeAndValue>, // Атрибуты, копируемые в любые сериализованные имена
}

#[derive(Debug)]
struct Certificate {
    raw: Vec<u8>,                             // Complete ASN.1 DER content
    raw_tbs_certificate: Vec<u8>,             // Certificate part of raw ASN.1 DER content
    raw_subject_public_key_info: Vec<u8>,    // DER encoded SubjectPublicKeyInfo
    raw_subject: Vec<u8>,                     // DER encoded Subject
    raw_issuer: Vec<u8>,                      // DER encoded Issuer

    signature: Vec<u8>,
    //signature_algorithm: SignatureAlgorithm,

    //public_key_algorithm: PublicKeyAlgorithm,
    //public_key: Option<Box<dyn PublicKey>>,    // Using trait object for dynamic dispatch

    version: u32,
    serial_number: u128,     // serial_number: Option<BigInt>,          // Type for big integers
    //issuer: Name,                        // Assuming pkix is a module with Name struct
    //subject: Name,
    not_before: SystemTime,                    // Using SystemTime for time representation
    not_after: SystemTime,
    //key_usage: KeyUsage,

    extensions: Vec<Extension>,          // Raw X.509 extensions
    extra_extensions: Vec<Extension>,    // Extensions to be copied raw into any marshaled certificates
    //unhandled_critical_extensions: Vec<asn1::ObjectIdentifier>, // List of extension IDs not fully processed

    //ext_key_usage: Vec<ExtKeyUsage>,           // Sequence of extended key usages
    //unknown_ext_key_usage: Vec<asn1::ObjectIdentifier>, // Encountered extended key usages unknown to this package

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
    //policy_identifiers: Vec<asn1::ObjectIdentifier>,
    //policies: Vec<OID>, // Assuming OID is defined
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
        //signature_algorithm: SignatureAlgorithm::default(), // Default value
        //public_key_algorithm: PublicKeyAlgorithm::default(), // Default value
        //public_key: None,
        version: 0,
        serial_number: 0u128,
        //issuer: Name::default(), // Assuming a default implementation
        //subject: Name::default(),
        not_before: SystemTime::now(),
        not_after: SystemTime::now(),
        //key_usage: KeyUsage::default(), // Default value
        extensions: Vec::new(),
        extra_extensions: Vec::new(),
        //unhandled_critical_extensions: Vec::new(),
        //ext_key_usage: Vec::new(),
        //unknown_ext_key_usage: Vec::new(),
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
        //policy_identifiers: vec![],
        //policies: vec![]
    };

    let mut input = ASN1String{ 0: der.to_vec()};
    // we read the SEQUENCE including length and tag bytes so that
	// we can populate Certificate.Raw, before unwrapping the
	// SEQUENCE so it can be operated on

    // Чтение ASN.1 элемента
    let mut input1 = input.clone();

    println!("parseCertificate input before read_asn1_element is : {:?}", &input);/*

    if !input.read_asn1_element(&mut input1, SEQUENCE) {
        //return Err("x509: malformed certificate".into());
        panic!("x509: malformed certificate");
    }
    println!("parseCertificate input after read_asn1_element is : {:?}", &input);
    cert.raw = input.0.clone();

    // Чтение основного элемента ASN.1
    if !input.read_asn1(&mut input1, SEQUENCE) {
        //return Err("x509: malformed certificate".into());
        panic!("x509: malformed certificate");
    }
    println!("parseCertificate input after read_asn1 is : {:?}", &input);



    let mut tbs = Vec::new(); // Подходящий тип для tbs

    //if !read_asn1_element(&mut tbs) {
        //return Err("x509: malformed tbs certificate".into());
    //}
    //cert.raw_tbs_certificate = tbs.clone();

    // Чтение версии
    //if !read_optional_asn1_integer(&mut tbs, &mut cert.version) {
        //return Err("x509: malformed version".into());
    //}
    //if cert.version < 0 {
        //return Err("x509: malformed version".into());
    //}

    cert.version += 1;
    if cert.version > 3 {
        return Err("x509: invalid version".into());
    }

    // Чтение серийного номера
    let serial = BigInt::new(); // Эквивалент создания нового большого числа
    if !read_asn1_integer(&mut tbs, &serial) {
        return Err("x509: malformed serial number".into());
    }
    cert.serial_number = Some(serial);

    // Чтение идентификатора алгоритма подписи
    let sig_ai_seq = Vec::new();
    if !read_asn1(&mut tbs, &mut sig_ai_seq) {
        return Err("x509: malformed signature algorithm identifier".into());
    }

    let outer_sig_ai_seq = Vec::new();
    if !read_asn1(&mut input, &mut outer_sig_ai_seq) {
        return Err("x509: malformed algorithm identifier".into());
    }
    if outer_sig_ai_seq != sig_ai_seq {
        return Err("x509: inner and outer signature algorithm identifiers don't match".into());
    }

    let sig_ai = parse_ai(sig_ai_seq)?; // Обработка идентификатора алгоритма
    cert.signature_algorithm = get_signature_algorithm_from_ai(sig_ai);

    // Чтение секвенции издателя
    let issuer_seq = Vec::new();
    if !read_asn1_element(&mut tbs, &mut issuer_seq) {
        return Err("x509: malformed issuer".into());
    }
    cert.raw_issuer = issuer_seq.clone();
    let issuer_rdns = parse_name(issuer_seq)?;
    cert.issuer.fill_from_rdn_sequence(issuer_rdns); // Предполагая, что эта функция существует

    Ok(cert)*/

    cert

}

// Пример реализации функций чтения ASN.1
//fn read_asn1_element(input: &mut Vec<u8>) -> bool {
    // Здесь будет логика обработки ASN.1 элементов
    //true // Обязательно замените на реальную логику
//}

//fn read_asn1(input: &mut Vec<u8>) -> bool {
    // Здесь будет логика обработки ASN.1
    //true // Обязательно замените на реальную логику
//}

//fn read_optional_asn1_integer(input: &mut Vec<u8>, version: &mut i32```rust
//) -> bool {
    // Здесь будет логика чтения необязательного ASN.1 целого числа
    //true // Обязательно замените на реальную логику
//}

pub fn check_certs(certs_chain: &[u8]) -> bool {
    // extract
    // divide input string into three slices
    println!("check_certs certs_chain is : {:?}", &certs_chain);

    let len_of_certs_chain = (certs_chain[0] as usize)*65536 + (certs_chain[1] as usize)*256 + (certs_chain[2] as usize);
    println!("check_certs len_of_certs_chain is : {:?}", len_of_certs_chain);
    println!("check_certs certs_chain.len() is : {:?}", certs_chain.len());

    if len_of_certs_chain != certs_chain.len() {
        return false;
    }

    let len_of_leaf_cert = (certs_chain[3] as usize)*65536 + (certs_chain[4] as usize)*256 + (certs_chain[5] as usize);
    println!("check_certs len_of_leaf_cert is : {:?}", len_of_leaf_cert);

    let leaf_cert_slice = &certs_chain[6..len_of_leaf_cert+6];
    println!("check_certs leaf_cert_slice is : {:?}", leaf_cert_slice);

    //let leaf_cert = parse_certificate(leaf_cert_slice); // leafCert, err := x509.ParseCertificate(leafCertSlice)
    //if leaf_cert.not_after.Before(time.Now()) || leaf_cert.not_before.After(time.Now()) {
        //false
    //}

    let start_index = len_of_leaf_cert + 8;
    let len_of_internal_cert = (certs_chain[start_index] as usize)*65536 + (certs_chain[start_index+1] as usize)*256 + (certs_chain[start_index+2] as usize);
    println!("check_certs len_of_internal_cert is : {:?}", len_of_internal_cert);

    let internal_cert_slice = &certs_chain[start_index + 3..start_index + len_of_internal_cert + 3];
    println!("check_certs internal_cert_slice is : {:?}", internal_cert_slice);

    //let internal_cert = parse_certificate(internal_cert_slice); // internalCert, err := x509.ParseCertificate(internalCertSlice)
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
    println!("certs_chain[start_index] is : {:?}", certs_chain[start_index]);
    println!("certs_chain[start_index+1] is : {:?}", certs_chain[start_index+1]);
    println!("certs_chain[start_index+2] is : {:?}", certs_chain[start_index+2]);
    println!("start_index is : {:?}", start_index);
    let root_cert_slice = &certs_chain[start_index + 3..start_index + len_of_root_cert+3];
    println!("check_certs root_cert_slice is : {:?}", root_cert_slice);

    //rootCert, err := x509.ParseCertificate(rootCertSlice)
    // if err != nil {
    // fmt.Printf("ParseCertificate (rootCertSlice) err is : %v\n", err.Error())
    // return false
    // }

    return true;
}