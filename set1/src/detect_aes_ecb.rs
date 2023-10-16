use super::utils::{get_file_path, hex_to_bytes, read_file};
use std::collections::HashMap;

pub fn detect_aes_ecb(filename: &str) {
    let contents = read_file(get_file_path(filename).to_str().unwrap());

    for line in contents.lines() {
        let mut occurrence: HashMap<Vec<u8>, u16> = HashMap::new();
        let decoded_bytes = hex_to_bytes(line);
        // println!("{:?}", decoded_bytes);
        for i in (0..decoded_bytes.len()).step_by(16) {
            let current_block = &decoded_bytes[i..(i + 16)];
            // println!("{:?}", current_block);

            *occurrence.entry(current_block.to_vec()).or_insert(0) += 1;
        }
        if occurrence.values().any(|x| *x > 1) {
            println!("{}", line);
        }
    }
}
#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    pub fn test_detect_aes_ecb() {
        assert_eq!(detect_aes_ecb("8.txt"), ());
    }
}
