use set2::cbc_bitflipping::format_data;
use set2::ecb_cut_paste::kv_parser_generic;
use set3::ctr::ctr_to_bytes;
use std::str::from_utf8;

use set1::utils::xor_vec_bytes;
fn main() {
    fn ctr(input: &[u8]) -> Vec<u8> {
        let key = "YELLOW SUBMARINE".as_bytes();
        ctr_to_bytes(input, key, 0)
    }
    let mut test_string = String::from("admin=true");
    let input = format_data("mydata");

    let ciphertext = ctr(input.as_bytes());

    let extra_len = input.len() - test_string.len();
    // let empty_str = String::from(" ").repeat(extra_len);
    // test_string.push_str(empty_str.as_str());

    let xored_wanted = xor_vec_bytes(&input.as_bytes().to_vec(), &test_string.as_bytes().to_vec());
    println!("{:?}", xored_wanted.len());
    let malformed_ciphertext = xor_vec_bytes(&xored_wanted, &ciphertext);

    let decrypted = ctr(malformed_ciphertext.as_slice());
    let plain = from_utf8(&*decrypted).unwrap();
    println!("{:?}", plain);
    let res = kv_parser_generic(plain, ";");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ctr_bitflipping() {
        main();
    }
}
