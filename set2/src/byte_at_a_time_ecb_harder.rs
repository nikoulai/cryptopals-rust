use super::byte_at_a_time_ecb_decryption::{encryption_oracle, Oracle};
use super::ecb_cbc_detection_oracle::generate_random_bytes;
use base64::{engine::general_purpose, Engine};
use rand::Rng;
use set1::aes_ecb::encrypt_aes_ecb;
use set1::utils::decode_b64_to_bytes;
use std::collections::HashMap;
use std::fmt::{Debug, Display};

const block_size: usize = 16;
pub fn create_encryption_oracle() -> Box<Oracle> {
    let mut rng = rand::thread_rng();
    let key = generate_random_bytes(block_size);
    let mut prefix = generate_random_bytes(rng.gen_range(0..33));

    let padded_encryption_oracle = move |plaintext: &[u8]| -> Vec<u8> {
        let mut input = prefix.clone();
        println!("{:?}", input);
        input.append(&mut plaintext.to_vec());
        encryption_oracle(input.as_slice(), key.as_slice())
    };

    Box::new(padded_encryption_oracle)
}
fn find_difference_index<T>(vec1: &[T], vec2: &[T]) -> Option<usize>
where
    T: PartialEq + Debug + Eq + Display,
{
    for (i, (a, b)) in vec1.iter().zip(vec2.iter()).enumerate() {
        // println!("{} {} {}", i, a, b);
        if a != b {
            return Some(i);
        }
    }
    // If the vectors are of different lengths, return the index of the first difference in length.
    if vec1.len() != vec2.len() {
        println!("Inside different length");
        return Some(std::cmp::min(vec1.len(), vec2.len()));
    }
    None // Vectors are equal
}

pub fn find_prefix_length(oracle: &mut Box<Oracle>) -> usize {
    let input1 = b"0";
    let input2 = b"1";

    let ciphertext1 = oracle(input1);
    let ciphertext2 = oracle(input2);
    let mut index = find_difference_index(&ciphertext1, &ciphertext2).unwrap();

    //first block they differ
    let block = index / block_size as usize;
    println!(
        "The ciphertexts differ at index {}, and block {}",
        index, block
    );

    let mut new_block = block;
    let mut prefix_len = 0;

    // while new_block == block {}
    for i in 1..block_size {
        let test_vector = vec![0u8; i as usize];
        let mut input1 = test_vector.to_owned();
        input1.push(0);
        let mut input2 = test_vector.to_owned();
        input2.push(1);

        let ciphertext1 = oracle(input1.as_slice());
        let ciphertext2 = oracle(input2.as_slice());
        let new_index = find_difference_index(&ciphertext1, &ciphertext2).unwrap();
        println!("New index {}, input length {}", new_index, i);
        if new_index > index {
            // print!("______________&&&&^^^^^^^{}", new_index - i as usize);
            // return new_index - i as usize;
            prefix_len = new_index - i;
            break;
        }
    }
    return prefix_len;
}

pub fn wrap_encryption_oracle<'a>(
    prefix_len: usize,
    oracle: &'a mut Box<Oracle>,
    //I couldn't use the type Oracle, because Expected trait, found type alias `Oracle`
) -> Box<dyn FnMut(&[u8]) -> Vec<u8> + 'a> {
    let pad_len = (block_size - prefix_len % block_size);
    let padding = vec![0u8; pad_len];
    let wrapped_encryption_oracle = move |plaintext: &[u8]| -> Vec<u8> {
        let mut input = padding.clone();
        println!("{:?}", input);
        input.append(&mut plaintext.to_vec());
        let ciphertext = oracle(input.as_slice());

        //try to strip ciphertext, to ignore padding + prefix
        return ciphertext[prefix_len + pad_len..].to_vec();
    };
    return Box::new(wrapped_encryption_oracle);
}
pub fn break_encryption_oracle() {
    let mut oracle = create_encryption_oracle();
    let len = find_prefix_length(&mut oracle);
    let mut wrapped_oracle = wrap_encryption_oracle(len, &mut oracle);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    pub fn test_create_encryption_oracle() {
        let mut oracle = create_encryption_oracle();
        oracle("fsfsfs".as_bytes());
    }

    #[test]
    pub fn test_break_oracle() {
        break_encryption_oracle();
    }
}
