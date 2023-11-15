use super::pkcs7_padding;
use crate::cbc_mode::{decrypt_aes_cbc, encrypt_aes_cbc};
use openssl::version::platform;
use set1::aes_ecb::{decrypt_aes_ecb, encrypt_aes_ecb};
use std::collections::HashMap;
use std::str::from_utf8;

const static_key: &str = "YELLOW SUBMARINE";

pub fn kv_parser(input: &str) -> HashMap<String, String> {
    kv_parser_generic(input, "&")
}
// pub fn kv_parser(input: &str) -> Vec<Vec<&str>> {
pub fn kv_parser_generic(input: &str, character: &str) -> HashMap<String, String> {
    let mut kv_map = HashMap::new();

    let pairs: Vec<_> = input
        .split(character)
        .collect::<Vec<&str>>()
        .iter()
        // .map(|s| s.split("=").collect::<(&str, &str)>()) //why this doesn't work?
        // .collect::<Vec<(&str, &str)>>();
        .map(|s| s.split("=").collect::<Vec<_>>())
        .collect();
    for p in &pairs {
        kv_map.insert(p[0].to_string(), p[1].to_string());
    }
    println!("{:?}", kv_map);
    // let key_value_pairs = pairs.iter().map(|s| s.split("=").collect::Vec<&str>())
    return kv_map;
}

pub fn profile_for(email: &str) -> String {
    let striped_email = email.replace("&", "").replace("=", "");
    return format!("email={}&uid=10&role=user", striped_email);
}

pub fn encrypt_encoded(encoded_text: &str) -> Vec<u8> {
    encrypt_aes_ecb(encoded_text.as_bytes(), static_key.as_bytes())
}

pub fn decrypt_encoded(ciphertext: Vec<u8>) -> HashMap<String, String> {
    let plaintext = decrypt_aes_ecb(ciphertext.as_slice(), static_key.as_bytes());
    println!("---{}", plaintext);
    kv_parser(plaintext.as_str())
}

pub fn exploit() -> String {
    //Produce the encrypted data for our user
    let test_email = "user@mail.com";
    let encoded_data = &profile_for(test_email);
    let mut encrypted_data = encrypt_encoded(encoded_data);

    //create a block of admin + padding
    let admin_block = pkcs7_padding::pkcs7_pad("admin", 16);
    let mut test_email = "user@mailx".to_string();
    test_email.push_str(from_utf8(&*admin_block).unwrap());
    let admin_block_encoded = profile_for(test_email.as_str());
    let mut admin_encrypted = encrypt_encoded(admin_block_encoded.as_str());
    let mut admin_encrypted_block_slice = &admin_encrypted[16..32];
    // println!(
    //     "{:?} {:?}",
    //     &admin_encrypted_block_slice,
    //     admin_encrypted_block_slice.len()
    // );
    let _ = encrypted_data.truncate(encrypted_data.len() - 16);

    encrypted_data.append(&mut admin_encrypted_block_slice.to_vec());

    // encrypted_data.append(&mut admin_text_encrypted_slice.to_owned().to_vec());
    let res = decrypt_encoded(encrypted_data);
    return res["role"].clone();
}

#[cfg(test)]
mod tests {

    use super::*;
    #[test]
    fn test_kv_parser() {
        let test_string = "foo=bar&baz=qux&zap=zazzle";
        kv_parser(test_string);
        // assert_eq!(
        //     kv_parser("foo=bar&baz=qux&zap=zazzle"),
        //     "wrong" // r###"{
        //             //         foo: 'bar',
        //             //         baz: 'qux',
        //             //         zap: 'zazzle'
        //             // }"###
        // )
    }

    #[test]
    fn test_profile_for() {
        let result = profile_for("foo@bar.com");
        assert_eq!(result, "email=foo@bar.com&uid=10&role=user")
    }

    #[test]
    fn test_decrypt_encoded() {
        let kv_map = decrypt_encoded(encrypt_encoded(profile_for("foo@bar.com").as_str()));
        println!("{:?}", kv_map["role"]);
    }

    #[test]
    fn test_exploit() {
        assert_eq!(exploit(), "admin");
    }
}
