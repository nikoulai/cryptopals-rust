use super::utils::{bytes_to_hex, hex_to_bytes};
fn fixed_xor(hex1: &str, hex2: &str) -> String {
    let bytes1 = hex_to_bytes(hex1);
    let bytes2 = hex_to_bytes(hex2);

    // let output_bytes = zip(bytes1,bytes2);
    //todo use utils
    let output_bytes = bytes1
        .iter()
        .zip(bytes2)
        .map(|(a, b)| a ^ b)
        .collect::<Vec<_>>();

    bytes_to_hex(&output_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fixed_xor() {
        assert_eq!(
            fixed_xor(
                "1c0111001f010100061a024b53535009181c",
                "686974207468652062756c6c277320657965"
            ),
            "746865206b696420646f6e277420706c6179"
        );
    }
}
