use super::utils::{decode_b64_to_bytes, get_file_path, read_file};

use openssl::symm::{decrypt, encrypt, Cipher};
use std::str::from_utf8;
//https://docs.rs/openssl/latest/openssl/symm/index.html
use aes::cipher::consts::U16;
use aes::cipher::{
    generic_array::GenericArray, Block, BlockCipher, BlockDecrypt, BlockEncrypt, BlockSizeUser,
    KeyInit,
};
use aes::Aes128;
pub fn decrypt_file_aes_ecb(file: &str, key: &[u8]) -> String {
    let b64_content = read_file(get_file_path(file).to_str().unwrap()).replace("\n", "");

    let content = decode_b64_to_bytes(b64_content.as_str());

    decrypt_aes_ecb(content.as_slice(), key)
}
pub fn decrypt_aes_ecb(message: &[u8], key: &[u8]) -> String {
    let cipher = Cipher::aes_128_ecb();

    // println!("######{:?} {:?}", message, key);
    let plain_bytes = decrypt(cipher, key, None, message).unwrap();

    from_utf8(plain_bytes.as_slice()).unwrap().to_string()
}
pub fn encrypt_aes_bytes(plaintext: &[u8], key: &[u8], block_size: usize) -> Vec<u8> {
    let key = GenericArray::from_slice(key);

    let cipher = Aes128::new(&key);

    let mut block = GenericArray::from_slice(plaintext).clone();
    cipher.encrypt_block(&mut block);
    return block.to_vec();
    // previous_block = Block::clone_from_slice(current_plain_block);
    // previous_block = GenericArray::from_slice(&*block);
    //
    // ciphertext.append(&mut block.to_vec().clone());
    // // println!("{:?}", ciphertext);
    // ciphertext
}
pub fn encrypt_aes_ecb(message: &[u8], key: &[u8]) -> Vec<u8> {
    let cipher = Cipher::aes_128_ecb();
    println!(
        "{:?} {:?} {:?} {:?}",
        &message,
        message.len(),
        &key,
        key.len()
    );
    let cipher_bytes = encrypt(cipher, key, None, message).unwrap();
    return cipher_bytes;
}
#[cfg(test)]
mod tests {
    use super::*;
    const file: &str = "7.txt";
    const key: &str = "YELLOW SUBMARINE";
    #[test]
    fn test_decrypt_aes_128_ecb() {
        assert_eq!(decrypt_file_aes_ecb(file, key.as_bytes()), test_string);
    }

    #[test]
    fn test_encrypt_aes_128_ecb() {
        let b64_content = read_file(get_file_path(file).to_str().unwrap()).replace("\n", "");

        let content = decode_b64_to_bytes(b64_content.as_str());

        assert_eq!(
            encrypt_aes_ecb(
                decrypt_aes_ecb(content.as_slice(), key.as_bytes()).as_bytes(),
                key.as_bytes()
            ),
            content
        );
    }

    const test_string: &str = "I'm back and I'm ringin' the bell \nA rockin' on the mike while the fly girls yell \nIn ecstasy in the back of me \nWell that's my DJ Deshay cuttin' all them Z's \nHittin' hard and the girlies goin' crazy \nVanilla's on the mike, man I'm not lazy. \n\nI'm lettin' my drug kick in \nIt controls my mouth and I begin \nTo just let it flow, let my concepts go \nMy posse's to the side yellin', Go Vanilla Go! \n\nSmooth 'cause that's the way I will be \nAnd if you don't give a damn, then \nWhy you starin' at me \nSo get off 'cause I control the stage \nThere's no dissin' allowed \nI'm in my own phase \nThe girlies sa y they love me and that is ok \nAnd I can dance better than any kid n' play \n\nStage 2 -- Yea the one ya' wanna listen to \nIt's off my head so let the beat play through \nSo I can funk it up and make it sound good \n1-2-3 Yo -- Knock on some wood \nFor good luck, I like my rhymes atrocious \nSupercalafragilisticexpialidocious \nI'm an effect and that you can bet \nI can take a fly girl and make her wet. \n\nI'm like Samson -- Samson to Delilah \nThere's no denyin', You can try to hang \nBut you'll keep tryin' to get my style \nOver and over, practice makes perfect \nBut not if you're a loafer. \n\nYou'll get nowhere, no place, no time, no girls \nSoon -- Oh my God, homebody, you probably eat \nSpaghetti with a spoon! Come on and say it! \n\nVIP. Vanilla Ice yep, yep, I'm comin' hard like a rhino \nIntoxicating so you stagger like a wino \nSo punks stop trying and girl stop cryin' \nVanilla Ice is sellin' and you people are buyin' \n'Cause why the freaks are jockin' like Crazy Glue \nMovin' and groovin' trying to sing along \nAll through the ghetto groovin' this here song \nNow you're amazed by the VIP posse. \n\nSteppin' so hard like a German Nazi \nStartled by the bases hittin' ground \nThere's no trippin' on mine, I'm just gettin' down \nSparkamatic, I'm hangin' tight like a fanatic \nYou trapped me once and I thought that \nYou might have it \nSo step down and lend me your ear \n'89 in my time! You, '90 is my year. \n\nYou're weakenin' fast, YO! and I can tell it \nYour body's gettin' hot, so, so I can smell it \nSo don't be mad and don't be sad \n'Cause the lyrics belong to ICE, You can call me Dad \nYou're pitchin' a fit, so step back and endure \nLet the witch doctor, Ice, do the dance to cure \nSo come up close and don't be square \nYou wanna battle me -- Anytime, anywhere \n\nYou thought that I was weak, Boy, you're dead wrong \nSo come on, everybody and sing this song \n\nSay -- Play that funky music Say, go white boy, go white boy go \nplay that funky music Go white boy, go white boy, go \nLay down and boogie and play that funky music till you die. \n\nPlay that funky music Come on, Come on, let me hear \nPlay that funky music white boy you say it, say it \nPlay that funky music A little louder now \nPlay that funky music, white boy Come on, Come on, Come on \nPlay that funky music \n";

    #[test]
    fn test_decrypt_aes_ecb() {
        // Test case 1
        let key1 = "yellowsubmarine";
        let plaintext1 = "Hello, World!";
        let ciphertext1 = encrypt_aes_ecb(plaintext1.as_bytes(), key1.as_bytes());
        assert_eq!(decrypt_aes_ecb(&ciphertext1, key1.as_bytes()), plaintext1);

        // Test case 2
        let key2 = "supersecretkeyyy"; // Assuming 128-bit key, so 16 chars/bytes
        let plaintext2 = "Rust is awesome!";
        let ciphertext2 = encrypt_aes_ecb(plaintext2.as_bytes(), key2.as_bytes());
        assert_eq!(decrypt_aes_ecb(&ciphertext2, key2.as_bytes()), plaintext2);

        // You can add more test cases in a similar fashion.
    }
}
