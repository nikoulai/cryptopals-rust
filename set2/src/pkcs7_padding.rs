pub fn pkcs7_pad(message: &str, block_size: u8) -> Vec<u8> {
    let pad_length: u8 = block_size - (message.len() as u8) % (block_size);
    let mut pad_vec = vec![pad_length; pad_length as usize];
    // print!("{:?}", pad_vec);
    let mut message_vec = message.as_bytes().to_vec();
    message_vec.append(&mut pad_vec);
    return message_vec.as_slice().to_owned();
}
pub fn pkcs7_pad_bytes(message_vec: &mut Vec<u8>, block_size: u8) {
    let pad_length: u8 = block_size - (message_vec.len() as u8) % (block_size);
    let mut pad_vec = vec![pad_length; pad_length as usize];
    message_vec.append(&mut pad_vec);
}
pub fn pkcs7_unpad_bytes(message_vec: &mut Vec<u8>) -> &mut Vec<u8> {
    let pad = message_vec.pop();
    // println!("{:?}", pad);
    match pad {
        None => (),
        Some(pad) => message_vec.truncate((message_vec.len() as u8 - pad + 1) as usize), //+1 Because we have already popped one
    }
    message_vec
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pkcs7_pad() {
        // let mut data = "12345678".to_string(); // assuming block size is 8
        // assert_eq!(pkcs7_pad(&mut data, 8), b"12345678");

        let mut data = "1234567".to_string(); // 1 character short of 8
        assert_eq!(pkcs7_pad(&mut data, 8), b"1234567\x01");

        let mut data = "1234567890123456".to_string(); // assuming block size is 16

        assert_eq!(
            pkcs7_pad(&data, 16),
            b"1234567890123456\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10"
        );

        let mut data = "".to_string();
        assert_eq!(pkcs7_pad(&mut data, 8), b"\x08\x08\x08\x08\x08\x08\x08\x08");
    }
}
