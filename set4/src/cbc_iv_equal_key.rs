use set1::utils::{block_size, xor_vec_bytes};
use set2::cbc_bitflipping::{encrypt_data_bytes, static_key};
use set2::cbc_mode::decrypt_aes_cbc_bytes;
use set2::ecb_cbc_detection_oracle::generate_random_bytes;
use set2::ecb_cut_paste::kv_parser_generic;
use set2::pkcs7_padding::pkcs7_unpad_bytes;
use std::fmt;
use std::fmt::Formatter;
use std::str::from_utf8;

#[derive(Debug, Clone)]
pub struct AsciiError(Vec<u8>);

impl fmt::Display for AsciiError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "Invalid Ascii character! {:?}", self)
    }
}
pub fn verify_ascii_compliance(plaintext: &[u8]) -> Result<(), AsciiError> {
    for byte in plaintext {
        if *byte >= 127 {
            // println!("The byte{}", byte);
            return Err(AsciiError(plaintext.to_vec().clone()));
        }
    }
    Ok(())
}
fn decrypt_data(data: Vec<u8>) -> Result<Vec<u8>, AsciiError> {
    let mut decrypted_text = decrypt_aes_cbc_bytes(
        data.as_slice(),
        static_key.as_bytes(),
        static_key.as_bytes(),
        16,
    );
    let text = pkcs7_unpad_bytes(&mut decrypted_text);
    verify_ascii_compliance(&text)?;
    return Ok(text.clone());
    // let text = from_utf8(text);
    // println!("decrypted text: {:?}", text);
    // println!("*******{:?}", text);
    // let res = kv_parser_generic(text.unwrap(), ";");
    // println!("iiiii{:?}", res);
    // return res["admin"].clone();
}

fn main() {
    // let input = generate_random_bytes(3 * block_size);

    //we need 3, but we pass 5 because the unpadding will fail, because of xoring with c4
    // so we need the last two blocks untouched
    let input: String = "YELLOW SUBMARINE".repeat(5);
    println!("{}, {:?}", input, input.as_bytes());
    let mut ciphertext = encrypt_data_bytes(input.as_bytes());

    // C_1, C_2, C_3 -> C_1, 0, C_1
    let zero_block = vec![0; block_size];
    ciphertext.splice(block_size..2 * block_size, zero_block);
    let c1 = ciphertext[0..block_size].to_vec().clone();
    ciphertext.splice(2 * block_size..3 * block_size, c1);

    println!("{:?}", &ciphertext);
    // let mut plaitext: Vec<u8>;
    let plaintext = match decrypt_data(ciphertext) {
        Ok(plaintext) => plaintext,
        Err(e) => {
            e.0
            // println!("{}", e);
        }
    };
    let key = xor_vec_bytes(
        &plaintext[0..block_size].to_vec(),
        &plaintext[2 * block_size..3 * block_size].to_vec(),
    );
    println!("^^^{:?}", key);
    println!("{:?}", static_key.as_bytes());
}

#[cfg(test)]
mod tests {

    use super::*;
    #[test]
    fn test_cbc_iv_equal_key() {
        main()
    }
}
