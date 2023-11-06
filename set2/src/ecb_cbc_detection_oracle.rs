use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
// pub fn encrypt_aes_cbc(plaintext: &[u8], key: &[u8], iv: &[u8], block_size: usize) -> String {
use super::cbc_mode::encrypt_aes_cbc;
use base64::{engine::general_purpose, Engine};
use set1::aes_ecb::encrypt_aes_ecb;
pub fn encryption_oracle(plaintext: &[u8]) -> String {
    let block_size = 16;
    let modes = ["ECB", "CBC"];

    let mut rng = rand::thread_rng();
    let mode = modes[rng.gen_range(0..2)];
    println!("{}", mode);
    let key = generate_random_bytes(block_size);
    let mut prefix = generate_random_bytes(rng.gen_range(5..11));
    let mut suffix = generate_random_bytes(rng.gen_range(5..11));
    println!("{:?}", plaintext);
    println!("{:?} {:?} {:?}", prefix, suffix, "");
    prefix.append(&mut plaintext.to_owned());
    prefix.append(&mut suffix);
    let full_plaintext = prefix;
    println!("{:?}", full_plaintext);
    let mut ciphertext: String;
    if mode == "ECB" {
        // ciphertext = String::from_utf8().unwrap();
        ciphertext = general_purpose::STANDARD.encode(encrypt_aes_ecb(plaintext, key.as_slice()))
    } else {
        let iv = generate_random_bytes(block_size);
        ciphertext = encrypt_aes_cbc(plaintext, &*key, &*iv, block_size as usize);
    }
    println!("{:?}", ciphertext);
    return ciphertext;
}
pub fn detection_oracle() {
    // -> String {
    let test_text = concat!(
        "AAAAAAAAAAA", // 11 As, random bytes are between 5-10, so I have to be sure we'll full the first block
        "AAAAAAAAAAA", // 11 As the same for the last
        "AAAAAAAAAAAAAAAA",
        "AAAAAAAAAAAAAAAA"
    );
    let block_size = 16;
    println!("_______");
    println!("------{:?}", &test_text);
    println!("------{:?}", &test_text.as_bytes().len());
    let ciphertext = encryption_oracle(test_text.as_bytes());
    let ciphertext_bytes = general_purpose::STANDARD.decode(ciphertext).unwrap();
    let ciphertext_size = ciphertext_bytes.len();
    let blocks = ciphertext_size / block_size;
    println!("{:?}", ciphertext_bytes);
    //compare two last blocks from end
    //iv may be prepended in cbc
    let block1 = &ciphertext_bytes[(blocks - 3) * block_size..(blocks - 2) * block_size];
    let block2 = &ciphertext_bytes[(blocks - 2) * block_size..(blocks - 1) * block_size];
    if block2 == block1 {
        println!("ECB");
        return;
    }
    println!("CBC");
    // println!("{:?} {:?}", block1, block2);
}
//todo move to utils
pub fn generate_random_bytes(len: i32) -> Vec<u8> {
    thread_rng()
        .sample_iter(&Alphanumeric)
        .take(len as usize)
        .map(u8::from)
        .collect()
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_selection() {
        // encryption_oracle("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".as_bytes());
        detection_oracle();
    }
}
