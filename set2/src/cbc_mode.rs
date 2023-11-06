use super::pkcs7_padding::pkcs7_pad;
use aes::cipher::consts::U16;
use aes::cipher::{
    generic_array::GenericArray, Block, BlockCipher, BlockDecrypt, BlockEncrypt, BlockSizeUser,
    KeyInit,
};
use aes::Aes128;
use base64::{engine::general_purpose, Engine};
use hex;
use set1::utils::{encode_b64_to_bytes, read_b64_file_to_bytes, xor_vec_bytes};
use std::str::from_utf8;

pub fn decrypt_file(filename: &str, key: &[u8], iv: &[u8], block_size: usize) -> String {
    let contents = read_b64_file_to_bytes(filename);
    decrypt_aes_cbc(contents.as_slice(), key, iv, block_size)
}

pub fn decrypt_aes_cbc(ciphertext: &[u8], key: &[u8], iv: &[u8], block_size: usize) -> String {
    let mut message: Vec<u8> = Vec::with_capacity(ciphertext.len());

    let blocks_number = ciphertext.len() / block_size;
    let mut previous_block = iv;
    let key = GenericArray::from_slice(key);

    let cipher = Aes128::new(&key);
    for i in 0..blocks_number {
        let current_cipher_block = &ciphertext[i * block_size..(i + 1) * block_size];

        let mut block = GenericArray::from_slice(current_cipher_block).clone();

        cipher.decrypt_block(&mut block);
        let mut xored_block = xor_vec_bytes(&block.to_vec(), &previous_block.to_vec());
        previous_block = current_cipher_block;

        message.append(&mut xored_block);
    }
    from_utf8(&message).unwrap().to_string()
}

pub fn encrypt_aes_cbc(plaintext: &[u8], key: &[u8], iv: &[u8], block_size: usize) -> String {
    let mut ciphertext: Vec<u8> = Vec::with_capacity(plaintext.len());
    let mut plaintext = from_utf8(plaintext).unwrap();

    let mut plaintext = pkcs7_pad(&mut plaintext, 16);
    // println!("{:?} {:?}", plaintext, plaintext.len());

    let blocks_number = plaintext.len() / block_size;

    let mut previous_block: &GenericArray<u8, U16> = GenericArray::from_slice(iv);

    // previous_block = Block::clone_from_slice(iv);
    let key = GenericArray::from_slice(key);

    let cipher = Aes128::new(&key);
    let mut block: Block<Aes128>; //GenericArray<u8, u16>;
    let mut xored_block: Vec<u8>;
    for i in 0..blocks_number {
        let current_plain_block = &plaintext[i * block_size..(i + 1) * block_size];

        xored_block = xor_vec_bytes(&current_plain_block.to_vec(), &previous_block.to_vec());

        block = GenericArray::from_slice(&*xored_block).clone();
        cipher.encrypt_block(&mut block);
        // previous_block = Block::clone_from_slice(current_plain_block);
        previous_block = GenericArray::from_slice(&*block);

        ciphertext.append(&mut block.to_vec().clone());
    }
    // println!("{:?}", ciphertext);

    general_purpose::STANDARD.encode(ciphertext)
    // from_utf8(&ciphertext).unwrap().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    const key: &str = "YELLOW SUBMARINE";
    const iv: &[u8; 16] = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
    #[test]
    pub fn test_decrypt_file_cbc() {
        let result_string = "I'm back and I'm ringin' the bell \nA rockin' on the mike while the fly girls yell \nIn ecstasy in the back of me \nWell that's my DJ Deshay cuttin' all them Z's \nHittin' hard and the girlies goin' crazy \nVanilla's on the mike, man I'm not lazy. \n\nI'm lettin' my drug kick in \nIt controls my mouth and I begin \nTo just let it flow, let my concepts go \nMy posse's to the side yellin', Go Vanilla Go! \n\nSmooth 'cause that's the way I will be \nAnd if you don't give a damn, then \nWhy you starin' at me \nSo get off 'cause I control the stage \nThere's no dissin' allowed \nI'm in my own phase \nThe girlies sa y they love me and that is ok \nAnd I can dance better than any kid n' play \n\nStage 2 -- Yea the one ya' wanna listen to \nIt's off my head so let the beat play through \nSo I can funk it up and make it sound good \n1-2-3 Yo -- Knock on some wood \nFor good luck, I like my rhymes atrocious \nSupercalafragilisticexpialidocious \nI'm an effect and that you can bet \nI can take a fly girl and make her wet. \n\nI'm like Samson -- Samson to Delilah \nThere's no denyin', You can try to hang \nBut you'll keep tryin' to get my style \nOver and over, practice makes perfect \nBut not if you're a loafer. \n\nYou'll get nowhere, no place, no time, no girls \nSoon -- Oh my God, homebody, you probably eat \nSpaghetti with a spoon! Come on and say it! \n\nVIP. Vanilla Ice yep, yep, I'm comin' hard like a rhino \nIntoxicating so you stagger like a wino \nSo punks stop trying and girl stop cryin' \nVanilla Ice is sellin' and you people are buyin' \n'Cause why the freaks are jockin' like Crazy Glue \nMovin' and groovin' trying to sing along \nAll through the ghetto groovin' this here song \nNow you're amazed by the VIP posse. \n\nSteppin' so hard like a German Nazi \nStartled by the bases hittin' ground \nThere's no trippin' on mine, I'm just gettin' down \nSparkamatic, I'm hangin' tight like a fanatic \nYou trapped me once and I thought that \nYou might have it \nSo step down and lend me your ear \n'89 in my time! You, '90 is my year. \n\nYou're weakenin' fast, YO! and I can tell it \nYour body's gettin' hot, so, so I can smell it \nSo don't be mad and don't be sad \n'Cause the lyrics belong to ICE, You can call me Dad \nYou're pitchin' a fit, so step back and endure \nLet the witch doctor, Ice, do the dance to cure \nSo come up close and don't be square \nYou wanna battle me -- Anytime, anywhere \n\nYou thought that I was weak, Boy, you're dead wrong \nSo come on, everybody and sing this song \n\nSay -- Play that funky music Say, go white boy, go white boy go \nplay that funky music Go white boy, go white boy, go \nLay down and boogie and play that funky music till you die. \n\nPlay that funky music Come on, Come on, let me hear \nPlay that funky music white boy you say it, say it \nPlay that funky music A little louder now \nPlay that funky music, white boy Come on, Come on, Come on \nPlay that funky music \n\u{4}\u{4}\u{4}\u{4}";
        assert_eq!(
            decrypt_file("10.txt", key.as_bytes(), iv, 16),
            result_string
        );
    }

    // #[test]
    // fn test_aes_cbc_decrypt() {
    //     // let new_key = hex::decode("2b7e151628aed2a6abf7158809cf4f3c").unwrap();
    //     // let new_iv = hex::decode("000102030405060708090A0B0C0D0E0F").unwrap();
    //     //
    //     // let ciphertext = hex::decode("7649abac8119b246cee98e9b12e9197d").unwrap();
    //     // let encrypted_text = encrypt_aes_cbc(plaintext.as_bytes(), key, iv, 16); // Assuming block size of 16
    //
    //     let new_key = hex::decode("2b7e151628aed2a6abf7158809cf4f3c").unwrap();
    //     let new_iv = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
    //     let plaintext = hex::decode("6bc1bee22e409f96e93d7e117393172a").unwrap();
    //     let ciphertext = hex::decode("7649abac8119b246cee98e9b12e9197d").unwrap();
    //
    //     // The function decrypt_aes_cbc should be defined elsewhere in your code,
    //     // similar to the encrypt_aes_cbc, but for decryption.
    //     let decrypted_text = decrypt_aes_cbc(&ciphertext, new_key.as_slice(), new_iv.as_slice(), 16);
    //     assert_eq!(decrypted_text, "6bc1bee22e409f96e93d7e117393172a");
    // }
    #[test]
    fn test_aes_cbc_encrypt() {
        const key: &str = "YELLOW SUBMARINE";
        const iv: &[u8; 16] = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
        // let iv = &[0u8; 16]; // An example IV of 16 zero bytes
        let block_size = 16;

        let contents = read_b64_file_to_bytes("10.txt");
        let mut plaintext = decrypt_aes_cbc(contents.as_slice(), key.as_bytes(), iv, block_size);
        plaintext.truncate(plaintext.len() - 4);
        // plaintext_bytes.to_vec().truncate(plaintext_bytes.len() - 4);
        println!("{:?}", plaintext);
        let res = encrypt_aes_cbc(plaintext.as_bytes(), key.as_bytes(), iv, block_size);

        println!("{:?}", res);

        // assert_eq!(res, contents);
    }
}
