use base64::{engine::general_purpose, Engine};
use hex;
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;

pub fn hex_to_bytes(hex_string: &str) -> Vec<u8> {
    hex::decode(hex_string).unwrap()
}

pub fn bytes_to_hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

#[warn(dead_code)]
pub fn xor_vec_bytes(bytes1: &Vec<u8>, bytes2: &Vec<u8>) -> Vec<u8> {
    bytes1
        .iter()
        .zip(bytes2)
        .map(|(a, b)| a ^ b)
        .collect::<Vec<_>>()
}

pub fn read_file(filename: &str) -> String {
    let mut file = File::open(filename).expect("File not found");
    let mut contents = String::new();
    file.read_to_string(&mut contents);

    return contents;
}

pub fn get_file_path(file_name: &str) -> PathBuf {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.push("../files/");
    d.push(file_name);

    return d;
}

pub fn decode_b64_to_bytes(a: &str) -> Vec<u8> {
    general_purpose::STANDARD.decode(a).unwrap()
}

pub fn bytes_to_chunks(bytes: &[u8], chunk_size: usize) -> Vec<&[u8]> {
    let chunks: Vec<&[u8]> = bytes.chunks(chunk_size).collect();
    println!("{:?}", chunks);
    return chunks;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exact_multiple() {
        let data = &[
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
            25, 26, 27, 28, 29, 30, 31, 32,
        ];
        let chunks = bytes_to_chunks(data, 16);
        assert_eq!(chunks.len(), 2);
        assert_eq!(
            chunks[0],
            &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]
        );
        assert_eq!(
            chunks[1],
            &[17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32]
        );
    }
}
