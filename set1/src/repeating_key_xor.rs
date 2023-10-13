use super::utils::bytes_to_hex;

pub fn repeating_key_xor(key: &str, text: &str) -> String {
    let xored: Vec<u8> = key
        .as_bytes()
        .iter()
        .cycle()
        .zip(text.as_bytes())
        .map(|(a, b)| a ^ b)
        .collect();

    bytes_to_hex(&xored)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_repeating_key_xor() {
        assert_eq!(repeating_key_xor("ICE", r"Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal"), "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f")
    }
}
