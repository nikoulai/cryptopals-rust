use byteorder::{BigEndian, WriteBytesExt};
use byteorder::{LittleEndian, ReadBytesExt}; // 1.2.7
use set1::aes_ecb::encrypt_aes_bytes;
use set1::utils::{decode_b64_to_bytes, xor_vec_bytes};

use std::str::{from_utf8, from_utf8_unchecked};

pub fn ctr_to_string(plaintext: &[u8], key: &[u8], nonce: u64) -> String {
    from_utf8(&*ctr_to_bytes(plaintext, key, nonce))
        .unwrap()
        .to_string()
}
pub fn ctr_to_bytes(plaintext: &[u8], key: &[u8], nonce: u64) -> Vec<u8> {
    let blocks_num = plaintext.len() / 16 + 1;
    let mut ctr_key: Vec<u8> = Vec::with_capacity(blocks_num * 16);
    let mut nonce_vec = vec![];
    nonce_vec.write_u64::<LittleEndian>(nonce).unwrap();
    for i in 0..(blocks_num) {
        let mut block_count = vec![];
        block_count.write_u64::<LittleEndian>(i as u64).unwrap();
        let mut concat = [nonce_vec.clone(), block_count].concat();
        let mut key_slice = encrypt_aes_bytes(concat.as_slice(), key, 16);
        ctr_key.append(&mut key_slice);
    }
    ctr_key.truncate(plaintext.len());
    // println!("******{:?}", ctr_key);
    xor_vec_bytes(&ctr_key, &plaintext.to_vec())
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_ctr() {
        assert_eq!(
            ctr_to_string(
                decode_b64_to_bytes(
                    "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==",
                )
                .as_slice(),
                "YELLOW SUBMARINE".as_bytes(),
                0,
            ),
            "Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby "
        );
    }
}
