use set2::ecb_cbc_detection_oracle::generate_random_bytes;
use std::str::{from_utf8, from_utf8_unchecked};
// https://www.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks
use super::md4::{
    convert_byte_vec_to_u32, convert_u32_to_byte_vec, digest_to_str, md4, md4_with_registers,
};
use rand::{thread_rng, Rng};

const data_string: &str =
    "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon";
pub fn md4_mac(key: &[u8], message: &[u8], skip_padding: bool) -> String {
    // let input = pad_message(&key.to_vec()).unwrap();
    // let hash1 = compute(input).unwrap();

    let mut input = Vec::with_capacity(key.len() + message.len());
    input.extend_from_slice(key);

    input.extend_from_slice(message);
    digest_to_str(&md4(input, skip_padding))
}
fn create_mac_function() -> Box<dyn FnMut(&[u8]) -> String> {
    let key = generate_random_bytes(rand::thread_rng().gen_range(5..30));
    let mac = move |message: &[u8]| md4_mac(key.as_slice(), message, false);

    Box::new(mac)
}

unsafe fn verify_mac(
    md4mac: &mut Box<dyn FnMut(&[u8]) -> String>,
    message: &[u8],
    hash: String,
) -> bool {
    let mac = md4mac(message);
    // println!("{}\n{}", mac, hash);

    if mac == hash {
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
fn padding<T: Into<Vec<u8>>>(input: T, mut custom_len: Box<dyn FnMut(&[u8]) -> usize>) -> Vec<u8> {
    let mut bytes = input.into().to_vec();
    let initial_bit_len = (custom_len(&*bytes) << 3) as u64;

    // Step 1. Append padding bits
    // Append one '1' bit, then append 0 ≤ k < 512 bits '0', such that the resulting message
    // length in bis is congruent to 448 (mod 512).
    // Since our message is in bytes, we use one byte with a set high-order bit (0x80) plus
    // a variable number of zero bytes.

    // Append zeros
    // Number of padding bytes needed is 448 bits (56 bytes) modulo 512 bits (64 bytes)
    bytes.push(0x80_u8);
    while (bytes.len() % 64) != 56 {
        bytes.push(0_u8);
    }

    // Everything after this operates on 32-bit words, so reinterpret the buffer.
    let mut w = crate::md4::convert_byte_vec_to_u32(bytes);

    // Step 2. Append length
    // A 64-bit representation of b (the length of the message before the padding bits were added)
    // is appended to the result of the previous step, low-order bytes first.
    w.push(initial_bit_len as u32); // Push low-order bytes first
    w.push((initial_bit_len >> 32) as u32);
    convert_u32_to_byte_vec(w)
}

unsafe fn main() {
    let mut sha_mac = create_mac_function();
    let initial_hex = sha_mac(data_string.as_bytes());
    println!("-----------------");
    // println!("{}", initial_hex);
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
    // println!("{:?}", subs);
    // subs.reverse();
    let registers: [u32; 4] = match subs.as_slice() {
        [a, b, c, d] => [*a, *b, *c, *d],
        _ => panic!("Vec<u32> does not have exactly 5 elements"),
    };

    // for i in 0usize..20 {
    for i in 0_usize..30 {
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

        let h = md4_with_registers(
            client_string,
            u32::to_be(registers[0]),
            u32::to_be(registers[1]),
            u32::to_be(registers[2]),
            u32::to_be(registers[3]),
            true,
        );

        let result = format!("{:08x}{:08x}{:08x}{:08x}", h[0], h[1], h[2], h[3]);

        // [i..] so we can skip the placeholder
        if verify_mac(&mut sha_mac, &malformed_data.as_slice()[i..], result) {
            println!("Success!!!!!!!!! for key length: {}", i);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::md4::convert_byte_vec_to_u32;

    #[test]
    pub fn test_break_length_extension_md4() {
        unsafe {
            main();
        }
    }
}
