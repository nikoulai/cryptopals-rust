use std::str::from_utf8;

pub fn pkcs7_pad(message: &mut str, block_size: usize) -> String {
    let pad_length: u8 = (message.len() % block_size) as u8;

    let pad_vec = vec![pad_length; pad_length as usize];
    let mut pad = from_utf8(pad_vec.as_slice()).unwrap();

    // let mut message_bytes = message.as_bytes().to_vec();
    let result = [message, pad].concat();
    println!("{}", result);
    return result;
    // println!("{:?}", message_bytes.append(&mut pad_vec));
    // message_bytes.append(&mut pad_vec);

    // return from_utf8(&message_bytes.to_owned().as_slice()).unwrap();

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
}
