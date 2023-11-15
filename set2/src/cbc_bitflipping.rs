use super::cbc_mode::{decrypt_aes_cbc_bytes, encrypt_aes_cbc};
use super::pkcs7_padding;
use crate::cbc_mode::encrypt_aes_cbc_bytes;
use crate::ecb_cut_paste::kv_parser_generic;
use crate::pkcs7_padding::pkcs7_unpad_bytes;
use openssl::version::platform;
use set1::aes_ecb::{decrypt_aes_ecb, encrypt_aes_ecb};
use set1::utils::xor_vec_bytes;
use std::collections::HashMap;
use std::str::{from_utf8, from_utf8_unchecked};

const static_key: &str = "1234444444444a44";
pub fn format_data(data: &str) -> String {
    let striped_data = data.replace(";", "").replace("=", "");
    let prefix = "comment1=cooking%20MCs;userdata=";
    let suffix = ";comment2=%20like%20a%20pound%20of%20bacon";

    // let prefix = "";
    // let suffix = "";
    let full_data = format!("{}{}{}", prefix, striped_data, suffix);
    // println!("Full data: {}", full_data);
    return full_data;
}

pub fn encrypt_data(data: &str) -> Vec<u8> {
    let block_size = 16;
    let formatted_data = format_data(data);
    // let padded_data = pkcs7_padding::pkcs7_pad(formatted_data.as_str(), block_size);

    // println!(" Padded: {:?}", padded_data);
    // println!("{:?}", formatted_data.as_bytes());
    encrypt_aes_cbc_bytes(
        formatted_data.as_bytes(),
        static_key.as_bytes(),
        static_key.as_bytes(),
        block_size as usize,
    )
}

pub unsafe fn decrypt_data(data: Vec<u8>) -> String {
    let mut decrypted_text = decrypt_aes_cbc_bytes(
        data.as_slice(),
        static_key.as_bytes(),
        static_key.as_bytes(),
        16,
    );
    let text = pkcs7_unpad_bytes(&mut decrypted_text);
    let text = from_utf8_unchecked(text);
    // println!("decrypted text: {:?}", text);
    println!("*******{:?}", text);
    let res = kv_parser_generic(text, ";");
    println!("iiiii{:?}", res);
    return "".to_string();
    // return res["admin"].clone();
}

unsafe fn bitflipping_attack() {
    let goal_bytes = "AAAAA;admin=true".as_bytes();
    let mut a_block = "AAAAAAAAAAAAAAAA";
    let input = format!("{}{}", a_block, a_block);
    let mut ciphertext = encrypt_data(input.as_str());
    // let cipher_len = ciphertext.len();
    // let index = cipher_len - padding_len - goal_len;
    // let blocks = ciphertext.len() / 16;

    let xored = xor_vec_bytes(&a_block.as_bytes().to_vec(), &goal_bytes.to_vec());
    println!("replacement:{:?} {}", xored, xored.len());
    // let xxx = xor_vec_bytes(&cipher_replacement.to_vec(), &cipher_bytes.to_vec());
    // println!("{:?}", from_utf8_unchecked(&*xxx));

    let cipher_bytes = &ciphertext[32..48];
    let cipher_replacement = xor_vec_bytes(&cipher_bytes.to_vec(), &xored.to_vec());

    // println!("ciphertext: {:?} {}", ciphertext, ciphertext.len());
    // ciphertext.splice(16..32, a_block.as_bytes().iter().cloned());
    ciphertext.splice(32..48, cipher_replacement.iter().cloned());
    // println!(" ciphertext {:?} {}", ciphertext, ciphertext.len());
    // println!(
    //     "xoring{:?} with {:?}",
    //     &a_block.as_bytes().to_vec(),
    //     &xored.to_vec()
    // );
    // let xored = xor_vec_bytes(&a_block.as_bytes().to_vec(), &xored.to_vec());
    // println!("{:?}", from_utf8(&*xored).unwrap());
    // for i in 0..ciphertext.len() / 16 {
    //     println!("{:?}", &ciphertext[(16 * i)..(i + 1) * 16]);
    // }
    // println!("ciphertext: {:?}", ciphertext);

    decrypt_data(ciphertext.to_vec());
}

#[cfg(test)]
mod tests {
    use super::*;

    const test_string: &str = "admin=true;";
    #[test]
    fn test_format_data() {
        format_data(test_string);
    }

    #[test]
    fn test_encrypt_data() {
        encrypt_data(test_string);
    }
    #[test]
    fn test_decrypt_data() {
        let ciphertext = encrypt_data(test_string);
        println!("{:?}", ciphertext);
        unsafe {
            decrypt_data(ciphertext);
        }
    }
    #[test]
    fn test_bitflipping_attack() {
        unsafe {
            bitflipping_attack();
        }
    }
}
