use rand::{thread_rng, Rng};
use set1::utils::decode_b64_to_bytes;
use set2::byte_at_a_time_ecb_decryption::Oracle;
use set2::cbc_mode::{decrypt_aes_cbc_bytes, encrypt_aes_cbc_bytes};
use set2::ecb_cbc_detection_oracle::generate_random_bytes;
use set2::pkcs7_padding::{pkcs7_pad_bytes, validate_and_strip_pkcs7_padding};
use std::str::{from_utf8, from_utf8_unchecked};

const block_size: usize = 16;
const strings: [&str; 10] = [
    "MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
    "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
    "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
    "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
    "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
    "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
    "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
    "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
    "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
    "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93",
];

// pub type Oracle = dyn FnMut(&[u8]) -> Vec<u8>;
pub fn create_oracles() -> (
    Box<dyn FnMut() -> (Vec<u8>, Vec<u8>)>, //Encryption that returns iv & ciphertext
    Box<dyn FnMut(&[u8]) -> Result<Vec<u8>, &'static str>>, //Decryption
) {
    let mut rng = thread_rng();
    let value = rng.gen_range(0..10);
    let string_to_encrypt = strings[value];
    let mut plaintext = decode_b64_to_bytes(string_to_encrypt);
    // let mut plaintext = "00000000000000000000000000000000123456789abcdef"
    //     .as_bytes()
    //     .to_vec();
    let key = generate_random_bytes(block_size);
    let iv = generate_random_bytes(block_size);
    // println!("{:?} {:?}", &key, &iv);
    let key = [
        69, 49, 53, 105, 117, 49, 121, 90, 65, 108, 90, 99, 73, 104, 103, 103,
    ]
    .to_vec();
    let iv = [
        74, 99, 78, 107, 122, 84, 53, 84, 98, 52, 72, 74, 122, 116, 71, 89,
    ]
    .to_vec();

    let key1 = key.clone();
    let iv1 = iv.clone();
    // let padded_encryption_oracle = move |plaintext: &[u8]| -> (Vec<u8>, Vec<u8>) {
    let padded_encryption_oracle = move || -> (Vec<u8>, Vec<u8>) {
        let ciphertext = encrypt_aes_cbc_bytes(&*plaintext, &*key, &*iv, block_size);

        (iv.clone(), ciphertext)
    };

    let decryption_oracle = move |ciphertext: &[u8]| -> Result<Vec<u8>, &'static str> {
        let plaintext = decrypt_aes_cbc_bytes(ciphertext, &*key1, &*iv1, block_size);
        validate_and_strip_pkcs7_padding(plaintext.as_slice())
    };

    (
        Box::new(padded_encryption_oracle),
        Box::new(decryption_oracle),
    )
}

pub unsafe fn padding_oracle_attack() {
    let (mut enc_oracle, mut dec_oracle) = create_oracles();

    let (iv, initial_ciphertext) = enc_oracle();
    let mut ciphertext = [iv.clone(), initial_ciphertext.clone()].concat();
    println!("ciphertext: {:?}", ciphertext);
    let num_blocks = ciphertext.len() / block_size;

    //to store the plaintext, remove one block for iv
    let mut plaintext: Vec<u8> = Vec::with_capacity(ciphertext.len() - block_size);

    let mut temp_intermediates: Vec<u8> = Vec::with_capacity(block_size);
    // println!("{:?}", ciphertext);

    //1 because we exclude first ciphertext block, which is the iv.
    for cur_block in (1..num_blocks).rev() {
        //clear the vector for current block, we need only this block's intermediate values
        temp_intermediates.clear();
        // let mut temp_intermediates: Vec<u8> = Vec::with_capacity(block_size);
        // let mut temp_intermediates: Vec<u8> = Vec::with_capacity(block_size);

        //just for reference/easier usage
        let prev_cipherblock =
            &ciphertext[((cur_block - 1) * block_size)..(cur_block) * block_size];
        for i in (0..16).rev() {
            //The padding we need to look for
            let wanted_padding: u8 = (block_size - i) as u8;
            // println!("Wanted padding {},", wanted_padding);

            for j in 0..=255 {
                //i == 15 because we want to exlude the possibility of passing the same ciphertext as the original
                // in the first try only. If we kept only the right condition, we would miss the block of the actual padding
                //If padding is x5x5x5x5x5 we would skip the 5th byte
                if i == 15 && j == prev_cipherblock[i] {
                    continue;
                }
                //strip decrypted blocks
                let mut malformed_ciphertext =
                    (&ciphertext[0..(cur_block + 1) * block_size]).to_vec();

                let mut malf_cipher_block = temp_intermediates
                    .iter()
                    .map(|x| x ^ wanted_padding)
                    .collect::<Vec<u8>>();
                malf_cipher_block.push(j);
                malf_cipher_block.reverse();

                malformed_ciphertext.splice(
                    (cur_block - 1) * block_size + i..cur_block * block_size,
                    malf_cipher_block.clone(),
                );

                if let Ok(_) = dec_oracle(malformed_ciphertext.as_slice()) {
                    println!("Malformed: {:?}", malformed_ciphertext);
                    println!(
                        "cur_block: {}, malformedciphert: {:?}",
                        cur_block,
                        malf_cipher_block.clone()
                    );
                    let intermediate = wanted_padding ^ j;
                    println!("wanted_padding: {}, j: {}", wanted_padding, j);
                    temp_intermediates.push(intermediate);
                    let p = prev_cipherblock[i] ^ intermediate;
                    println!(
                        "prev_cipherblock[i]: {},intermediate: {}, p: {}",
                        prev_cipherblock[i], intermediate, p
                    );
                    println!("Char: {:?}", from_utf8(&[p]));
                    plaintext.push(p);
                    break;
                }
            }
        }
    }
    plaintext.reverse();
    // let plaintext = validate_and_strip_pkcs7_padding(&*plaintext).unwrap();
    println!("{:?}", from_utf8_unchecked(plaintext.as_slice()));
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    pub fn test_encrypt() {
        unsafe {
            padding_oracle_attack();
        }
        // let x = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        // let y = x[0..5][1];
        // println!("{}", y);
    }
}
