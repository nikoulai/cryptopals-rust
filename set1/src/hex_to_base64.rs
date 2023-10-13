use base64::{engine::general_purpose, Engine};
use hex;

fn hex_to_base64(hex_string: &str) -> String {
    //todo - use utils
    let bytes = hex::decode(hex_string).unwrap();
    general_purpose::STANDARD.encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hex_to_base64() {
        assert_eq!(
				hex_to_base64("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"),
				"SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
			);
    }
}
