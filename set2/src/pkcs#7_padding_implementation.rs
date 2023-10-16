pub fn pkcs7_pad(message: &mut str, block_size: u16) -> &mut str {
    let pad_length = message.len() % block_size;

    let pad_vec: Vec<u8> = vec![pad_length; pad_length];

    let mut message_bytes =  message.as_bytes().to_vec();
    println!("{:?}",
    message_bytes.append(pad_vec));
    message_bytes.append(pad_vec);


#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_pkcs7_pad() {
        let mut data = "12345678".to_string(); // assuming block size is 8
        pkcs7_pad(&mut data, 8);
        assert_eq!(data, "12345678");

        let mut data = "1234567".to_string(); // 1 character short of 8
        pkcs7_pad(&mut data, 8);
        assert_eq!(data, "1234567\x01");

        let mut data = "1234567890123456".to_string(); // assuming block size is 16
        pkcs7_pad(&mut data, 16);
        assert_eq!(
            data,
            "1234567890123456\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10"
        );

        let mut data = "".to_string();
        pkcs7_pad(&mut data, 8);
        assert_eq!(data, "\x08\x08\x08\x08\x08\x08\x08\x08");
    }
}
