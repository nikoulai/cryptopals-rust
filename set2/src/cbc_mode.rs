use set1::utils::{get_file_path, read_file};
use set1::AES_ECB::decrypt_aes_ecb;

pub fn decrypt_file(filename: &str) -> &str {
    println!("Decrypting file: {}", filename);
    let contents = read_file(get_file_path(filename).to_str().unwrap());
    return contents;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    pub fn test_decrypt_file_cbc() {
        assert_eq(decrypt_file("10.txt"), "");
    }
}
