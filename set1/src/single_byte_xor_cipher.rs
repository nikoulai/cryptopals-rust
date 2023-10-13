use super::utils::hex_to_bytes;
use std::collections::HashMap;
use std::str;

// enum scoring {
//     character_frequency,
// }

pub fn single_bytes_xor_cipher(hex_string: &str) -> (String, u8) {
    let text_bytes = hex_to_bytes(hex_string);
    // let bytes_length = text_bytes.len();
    let mut score = f32::MAX;
    let mut highest_string: String = String::from("");
    let mut char = 0;
    for i in 0..255 {
        let decoded_bytes = text_bytes.iter().map(|&ch| ch ^ i).collect::<Vec<_>>();

        let res = String::from_utf8(decoded_bytes).unwrap_or(String::from(""));

        if res.is_empty() {
            continue;
        }

        // println!("The decoded string: {}", res);
        let char_freq = get_char_freq(&res.as_str());
        let temp_score = variation_distance(char_freq);
        if temp_score < score {
            score = temp_score;
            highest_string = res;
            char = i;
        }
    }
    return (String::from(highest_string),char);
}

pub(crate) fn variation_distance(testing: HashMap<char, f32>) -> f32 {
    let expected: HashMap<char, f32> = HashMap::from([
        ('a', 8.2),
        ('e', 12.7),
        ('i', 6.9),
        ('o', 7.5),
        ('u', 2.8),
        ('t', 9.1),
        ('n', 6.7),
        ('s', 6.3),
        ('h', 6.1),
        ('r', 6.0),
        ('d', 4.3),
        ('l', 4.0),
        ('c', 2.8),
        ('m', 2.4),
        ('w', 2.4),
        ('f', 2.2),
        ('y', 2.0),
        ('g', 2.0),
        ('p', 1.9),
        ('b', 1.5),
        ('v', 1.0),
        ('k', 0.8),
        ('j', 0.15),
        ('x', 0.15),
        ('q', 0.10),
        ('z', 0.07),
    ]);

    let mut score = 0.0;
    for key in expected.keys() {
        score += expected.get(&key).unwrap() - testing.get(&key).unwrap_or(&0.0);
    }

    return score;
}
pub fn get_char_freq(text: &str) -> HashMap<char, f32> {
    let mut char_freq: HashMap<char, f32> = HashMap::new();

    for ch in text.chars() {
        *char_freq.entry(ch).or_insert(1.0) += 1.0;
        // if char_freq.contains_key(&ch){
        //     *char_freq.get_mut(&ch).unwrap() += 1.0;
        // }
        // else{
        //
        //     char_freq.insert(ch,1.0);
        // }
    }

    // print!("The char frequency:");
    // for (key, value) in &char_freq {
    //     println!("{}: {}", key, value);
    // }
    return char_freq;
}

#[cfg(test)]
mod tests {

    #[test]
    fn test_single_bytes_xor_cipher() {
        let (res,char) = super::single_bytes_xor_cipher(
            "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
        );
        assert_eq!(
            res,
            "Cooking MC's like a pound of bacon"
        );
    }

    #[test]
    fn test_get_char_frequency() {
        assert_eq!(
            super::get_char_freq("hello"),
            super::HashMap::from([('h', 1.0), ('e', 1.0), ('l', 2.0), ('o', 1.0)])
        );
    }
}
