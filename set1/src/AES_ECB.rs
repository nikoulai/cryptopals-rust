use super::utils::{decode_b64_to_bytes, get_file_path, read_file};
use openssl::symm;
use openssl::symm::{decrypt, Cipher};
use std::str::from_utf8;
//https://docs.rs/openssl/latest/openssl/symm/index.html

pub fn decrypt_aes_ecb(file: &str, key: &str) -> String {
    let cipher = Cipher::aes_128_ecb();

    let b64_content = read_file(get_file_path(file).to_str().unwrap()).replace("\n", "");
    let content = decode_b64_to_bytes(b64_content.as_str());

    let plain_bytes = decrypt(cipher, key.as_bytes(), None, content.as_slice()).unwrap();

    from_utf8(plain_bytes.as_slice()).unwrap().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decrypt_aes_128_ecb() {
        assert_eq!(
            decrypt_aes_ecb("7.txt", "YELLOW SUBMARINE"),
            "Now that the party is jumping\n"
        );
    }
}
