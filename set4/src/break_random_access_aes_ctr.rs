use rand::{thread_rng, Rng};
use set1::utils::read_b64_file_to_bytes;
use set1::utils::{decode_b64_to_bytes, xor_vec_bytes};
use set2::byte_at_a_time_ecb_decryption::Oracle;
use set2::cbc_mode::{decrypt_aes_cbc_bytes, encrypt_aes_cbc_bytes};
use set2::ecb_cbc_detection_oracle::generate_random_bytes;
use set2::pkcs7_padding::{pkcs7_pad_bytes, validate_and_strip_pkcs7_padding};

use set1::aes_ecb::decrypt_file_aes_ecb;
use set3::ctr;
use set3::ctr::ctr_to_bytes;
use std::str::{from_utf8, from_utf8_unchecked};

//*********************
// providing the ciphertext itself as the new plaintext will give back plaintext we’re after.
const block_size: usize = 16;
const nonce: u64 = 0;
fn edit(ciphertext: &[u8], key: &[u8], offset: usize, newtext: &[u8]) -> Vec<u8> {
    let mut plaintext = ctr_to_bytes(ciphertext, key, nonce);

    let extra_positions: i32 = (offset as i32 + newtext.len() as i32 - ciphertext.len() as i32);
    if extra_positions > 0 {
        println!("Extra positions");
        let extra = vec![0; extra_positions as usize];
        plaintext.extend_from_slice(extra.as_slice());
    }

    let replace_range = offset..offset + (newtext.len());
    //todo can this used to append to the text (in the end of text )
    plaintext.splice(replace_range, newtext.iter().cloned());
    println!("{}", from_utf8(&*plaintext).unwrap());
    let newciphertext = ctr_to_bytes(plaintext.as_slice(), key, nonce);

    newciphertext
}
pub fn create_function_and_ciphertext(
    plaintext: &[u8],
) -> (Box<dyn FnMut(&[u8], &[u8], usize) -> (Vec<u8>)>, Vec<u8>) {
    let aes_key = generate_random_bytes(block_size);

    let ciphertext = ctr_to_bytes(plaintext, aes_key.as_slice(), 0);
    // let aes_key1 = aes_key.clone();

    let seek = move |ciphertext: &[u8], newplaintext: &[u8], offset: usize| -> (Vec<u8>) {
        let ciphertext = edit(ciphertext, aes_key.as_slice(), offset, newplaintext);

        ciphertext
    };

    (Box::new(seek), ciphertext)
}

fn main() {
    let file = "25.txt";
    let key: &str = "YELLOW SUBMARINE";
    let input = decrypt_file_aes_ecb(file, key.as_bytes());
    println!("{}", input);
    println!("***********");
    let (mut seek, initial_ciphertext) = create_function_and_ciphertext(input.as_bytes());

    let init_ciphertext_len = initial_ciphertext.len() as u8;
    let new_input = vec![0u8, init_ciphertext_len];
    let new_ciphertext = seek(&*initial_ciphertext, &*new_input, 0);

    let plaintext = xor_vec_bytes(&initial_ciphertext, &new_ciphertext);

    println!("{}", from_utf8(&*plaintext).unwrap());
    // println!("{:?}", input);
    // let initial_ciphertext = ctr_to_bytes()
    // let contents = read_b64_file_to_bytes("25.txt");
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    pub fn test_edit() {
        let plaintext = "Random plaintext";
        const key: &str = "YELLOW SUBMARINE";
        let ciphertext = ctr_to_bytes(plaintext.as_bytes(), key.as_bytes(), 0);

        let newcipher = edit(ciphertext.as_slice(), key.as_bytes(), 0, "hi".as_bytes());

        let newplaintext = ctr_to_bytes(newcipher.as_slice(), key.as_bytes(), 0);

        assert_eq!(from_utf8(&*newplaintext).unwrap(), "hindom plaintext");

        //test appending
        let newcipher = edit(
            ciphertext.as_slice(),
            key.as_bytes(),
            plaintext.len() - 1,
            "hi".as_bytes(),
        );

        let newplaintext = ctr_to_bytes(newcipher.as_slice(), key.as_bytes(), 0);

        // assert_eq!(from_utf8(&*newplaintext).unwrap(), "hindom plaintext");
        let mut res = String::from_utf8(Vec::from(&*newplaintext)).unwrap();
        println!("{:?}{}", res.truncate(res.len() - 10), "***");
    }
    #[test]
    pub fn test_random_access_ctr() {
        main();
        // let x = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        // let y = x[0..5][1];
        // println!("{}", y);
    }
}
