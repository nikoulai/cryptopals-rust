use super::ecb_cbc_detection_oracle::generate_random_bytes;
use base64::{engine::general_purpose, Engine};
use set1::aes_ecb::encrypt_aes_ecb;
use set1::utils::decode_b64_to_bytes;
use std::collections::HashMap;

pub type Oracle = dyn FnMut(&[u8]) -> Vec<u8>;
static unknown_string_b64: &str = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK";

const static_key: &str = "YELLOW SUBMARINE";
pub fn encryption_oracle(plaintext: &[u8], key: &[u8]) -> Vec<u8> {
    let block_size = 16;
    let mut unknown_string_bytes = decode_b64_to_bytes(unknown_string_b64);
    let mut plaintext_vec = plaintext.to_vec();
    plaintext_vec.append(&mut unknown_string_bytes);
    // unknown_string_bytes.append(&mut plaintext.to_vec());
    // let text = unknown_string_bytes;
    let ciphertext = encrypt_aes_ecb(plaintext_vec.as_slice(), key);

    // println!("{:?}", ciphertext);
    return ciphertext;
}

pub fn decryption_oracle(oracle: Option<&mut Box<Oracle>>) {
    // let key = generate_random_bytes(16);
    let block_size = detect_block_size();
    let test_text = concat!("AAAAAAAAAAAAAAAA", "AAAAAAAAAAAAAAAA", "AAAAAAAAAAAAAAAA");
    let mut ciphertext_bytes = encryption_oracle(test_text.as_bytes(), static_key.as_bytes());
    let block1 = &ciphertext_bytes[(0) * block_size..(1) * block_size];
    let block2 = &ciphertext_bytes[(1) * block_size..(2) * block_size];
    println!("{:?}", block1);
    println!("{:?}", block2);
    if block1 == block2 {
        println!("{:?}", "ECB");
    } else {
        println!("{:?}", "=----");
    }

    //unknown text len + padding
    let mut unknown_text_len =
        encryption_oracle(Vec::new().as_slice(), static_key.as_bytes()).len();

    // let alphabet =
    // "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'\"?.,; ".to_string();
    let alphabet = r###"ABCDEFGHIJKLMNOPQRSTUVWXYZ\abcdefghijklmnopqrstuvwxyz0123456789-)(*&^%$#@!~'" .?;,
        "###;
    // let mut dictionary: HashMap<Vec<u8>, u16> = HashMap::new();
    let mut dictionary: Vec<String> = Vec::with_capacity(alphabet.len());

    // let test_text = concat!("AAAAAAAAAAAAAAAA", "AAAAAAAAAAAAAAAA", "AAAAAAAAAAAAAAAA");
    let mut detected_text: String = "".to_string();
    for i in 0..unknown_text_len {
        // for i in 0..16 {
        let running_block = detected_text.len() / block_size;
        for mut l in alphabet.chars() {
            let c = l;
            let mut a_repetitions = block_size - detected_text.len() % block_size - 1;
            // if a_repetitions == 0 {
            //     a_repetitions = block_size - 1;
            // }
            let mut test_text;
            test_text = "A".repeat(a_repetitions);
            println!("{:?}", test_text);

            //cipher_text to compare the other
            let base_ciphertext = encryption_oracle(test_text.as_bytes(), static_key.as_bytes());
            test_text.push_str(&mut detected_text.to_owned());
            test_text.push_str(&mut c.to_string());

            println!("{:?} {:?} {:?}", i, a_repetitions, test_text);
            println!(
                "{:?} {:?} {:?}",
                block_size,
                detected_text.len(),
                block_size - detected_text.len() % block_size - 1
            );
            let ciphertext = encryption_oracle(test_text.as_bytes(), static_key.as_bytes());
            if ciphertext[running_block * 16..(running_block + 1) * 16]
                == base_ciphertext[running_block * 16..(running_block + 1) * 16]
            {
                println!("Equal for: {:?}", test_text);
                detected_text.push(c);
                break;
            }
            dictionary.push(test_text);
        }
        // println!("{:?}", dictionary);
    }
    println!("Final detected text: {:?}", detected_text);
}

pub fn detect_block_size() -> usize {
    let mut ciphertext_len = encryption_oracle(Vec::new().as_slice(), static_key.as_bytes()).len();

    for i in 0..17 {
        let input = "A".repeat(i);
        let mut new_ciphertext_len =
            encryption_oracle(input.as_bytes(), static_key.as_bytes()).len();
        if new_ciphertext_len - ciphertext_len > 1 {
            return new_ciphertext_len - ciphertext_len;
        }
    }
    return 0;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    pub fn test_detect_block_size() {
        detect_block_size();
    }

    #[test]
    pub fn test_decrypt_ecb_byte() {
        decryption_oracle(None);
    }
}
