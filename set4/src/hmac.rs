use super::sha1::{compute, pad_message, Block};
use crate::break_sha1_mac_length_extension::my_padding;
use crate::sha1_mac::sha1_mac;
use set1::utils::{parse_hex_string_to_bytes, xor_vec_bytes};

fn sha1_hash(message: &[u8]) -> String {
    // compute(pad_message(&message.to_vec()).unwrap()).unwrap()

    let input = Block::from_message(&my_padding(&message)).unwrap();
    let hash = compute(input).unwrap();

    // println!("{:?}", hash.clone().as_bytes().len());

    return hash;
}
fn compute_block_sized_key(
    mut key: &[u8],
    hash_function: fn(&[u8]) -> String,
    block_size: usize,
) -> Vec<u8> {
    let mut key_: Vec<u8> = key.to_vec();
    if key_.len() > block_size {
        key_ = hash_function(key).into_bytes()
    }

    if key_.len() < block_size {
        key_.append(&mut vec![0u8; block_size - key.len()]);
    }

    key_
}

pub fn sha1_hmac(key: &[u8], message: &[u8]) -> String {
    hmac(key, message, sha1_hash, 64)
}
//https://en.wikipedia.org/wiki/HMAC
fn hmac(key: &[u8], message: &[u8], hash: fn(&[u8]) -> String, block_size: usize) -> String {
    let block_sized_key = compute_block_sized_key(key, hash, block_size);

    let mut o_key_pad = xor_vec_bytes(&block_sized_key, &vec![0x5cu8; block_size]); // Outer padded key
    let mut i_key_pad = xor_vec_bytes(&block_sized_key, &vec![0x36u8; block_size]); // Inner padded key

    i_key_pad.extend_from_slice(message);

    let int_res = parse_hex_string_to_bytes(sha1_hash(i_key_pad.as_slice()).as_str());

    // println!("-int res-{:X?}", int_res);
    o_key_pad.extend_from_slice(int_res.as_slice());

    sha1_hash(o_key_pad.as_slice())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pad(input: Vec<u8>, block_size: usize) -> Vec<u8> {
        let mut padded = input.clone();
        while padded.len() < block_size {
            padded.push(0u8);
        }
        padded
    }

    // #[test]
    // fn test_shorter_key_padding() {
    //     // Test when the input key is shorter than the block size
    //     let key = vec![0x01, 0x02, 0x03];
    //     let block_size = 10;
    //     let hash = |data: &[u8]| -> Vec<u8> {
    //         let res = compute(pad_message(&data.to_vec()).unwrap());
    //         res.unwrap().into_bytes()
    //     };
    //
    //     let result = compute_block_sized_key(&*key.clone(), hash, block_size);
    //     let expected = pad(key, block_size);
    //     assert_eq!(result, expected);
    // }

    #[test]
    fn test_sha1_hash() {
        let input = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".as_bytes();
        assert_eq!(
            "84983E441C3BD26EBAAE4AA1F95129E5E54670F1".to_lowercase(),
            sha1_hash(input)
        );
    }

    #[test]
    fn test_hmac() {
        // Test vectors from RFC 2202 (HMAC-SHA-1)
        let key = b"key";
        let message = "Sample message for keylen=blocklen";
        let key: Vec<u8> = vec![
            00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C,
            0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A,
            0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
            0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F,
        ];

        let result = hmac(&key, message.as_bytes(), sha1_hash, 64);
        // // assert_eq!(result, expected_result);
        // println!("{:?}", result);
        assert_eq!(
            result.as_str(),
            "5FD596EE78D5553C8FF4E72D266DFD192366DA29".to_lowercase()
        );
    }
}
