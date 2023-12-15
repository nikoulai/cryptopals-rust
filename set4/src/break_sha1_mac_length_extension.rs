use crate::sha1_mac::sha1_mac;
use set2::cbc_mode::encrypt_aes_cbc_bytes;
use set2::ecb_cbc_detection_oracle::generate_random_bytes;
use std::str::{from_utf8, from_utf8_unchecked};
// https://www.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks
use super::sha1::{compute, compute_with_registers, pad_message, Block};
use rand::{thread_rng, Rng};

const data_string: &str =
    "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon";
fn create_mac_function() -> Box<dyn FnMut(&[u8]) -> String> {
    let key = generate_random_bytes(rand::thread_rng().gen_range(5..20));
    let mac = move |message: &[u8]| sha1_mac(key.as_slice(), message);

    Box::new(mac)
}

unsafe fn verify_mac(
    sh1mac: &mut Box<dyn FnMut(&[u8]) -> String>,
    message: &[u8],
    hash: String,
) -> bool {
    // println!("{}\n{}", sh1mac(message), hash);
    if sh1mac(message) == hash {
        println!("{}", from_utf8_unchecked(message));
        return true;
    }
    false
}
pub(crate) fn my_padding(input: &[u8]) -> Vec<u8> {
    padding(input, Box::new(|x: &[u8]| x.len()))
}

//extra len is in bytes
fn my_padding_with_extra_len(input: &[u8], extra_len: usize) -> Vec<u8> {
    padding(input, Box::new(move |x: &[u8]| x.len() + extra_len))
}
fn padding(input: &[u8], mut custom_len: Box<dyn FnMut(&[u8]) -> usize>) -> Vec<u8> {
    let block_size = 64; //bytes
    let length_bytes = 8;

    let input_size = input.len();
    let custom_input_size = custom_len(input);

    let mut padding_length: i64 = (block_size - input_size % block_size) as i64 - length_bytes;
    if padding_length <= 0 {
        padding_length = block_size as i64 + padding_length
    }

    let mut padded_message =
        Vec::with_capacity(input_size + padding_length as usize + length_bytes as usize);

    padded_message.extend_from_slice(input);
    padded_message.push(0x80);
    let padding_zeros = vec![0u8; padding_length as usize - 1];
    padded_message.extend_from_slice(padding_zeros.as_slice());
    //8 byte field in big endian, showing the number of bits (* 8) of input
    padded_message.extend_from_slice(&*((custom_input_size * 8) as u64).to_be_bytes().as_slice());

    return padded_message;
    // Block::from_message(&padded_message)
}

unsafe fn main() {
    let mut sha_mac = create_mac_function();
    let initial_hex = sha_mac(data_string.as_bytes());

    let string_to_add = ";admin=true";

    //start the attack
    //split hash into the register values
    let mut subs = initial_hex
        .as_bytes()
        .chunks(8) //32bit
        .map(std::str::from_utf8)
        .map(|x| x.unwrap())
        .map(|x| u32::from_str_radix(x, 16))
        .collect::<Result<Vec<u32>, _>>()
        .unwrap();
    // subs.reverse();
    let registers: [u32; 5] = match subs.as_slice() {
        [a, b, c, d, e] => [*a, *b, *c, *d, *e],
        _ => panic!("Vec<u32> does not have exactly 5 elements"),
    };

    for i in 0usize..20 {
        println!("Trying for length: {}", i);

        let mut placeholder = "A".repeat(i);
        placeholder.push_str(data_string);
        let mut malformed_data = placeholder.as_bytes().to_vec();
        let data_len = malformed_data.len();

        //0 because the add as prefix a placeholder for the secret
        // I used a placed holder as a workaround for the aligning of the padding, else I would have to remove some 0 aka write a new padding function (is theere another way?)
        malformed_data = my_padding_with_extra_len(malformed_data.as_slice(), 0);

        //server will prepend the secret and add the padding
        malformed_data.append(&mut string_to_add.as_bytes().to_vec());

        let client_string = my_padding_with_extra_len(
            string_to_add.as_bytes(),
            my_padding("A".repeat(data_len).as_bytes()).len(),
        );

        let result =
            match compute_with_registers(Block::from_message(&client_string).unwrap(), registers) {
                Ok(x) => x,
                Err(_) => String::new(),
            };

        // [i..] so we can skip the placeholder
        if verify_mac(&mut sha_mac, &malformed_data.as_slice()[i..], result) {
            println!("Success!!!!!!!!! for key length: {}", i);
        }
    }
    // println!("{:?}", ((data_string.len() * 8) as u64).to_be_bytes());
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    pub fn test_sha1_padding() {
        let input = b"input";
        assert_eq!(
            Block::from_message(&my_padding(input)),
            pad_message(&input.to_vec())
        )
    }

    #[test]
    pub fn test_break_length_extension_sha() {
        unsafe {
            main();
        }
    }

    #[test]
    pub fn test_data_string_padding() {
        let input = data_string.as_bytes();
        println!("{:?}", &my_padding_with_extra_len(input, 1));
        assert_eq!(
            Block::from_message(&my_padding(input)),
            pad_message(&input.to_vec())
        )
    }
}
