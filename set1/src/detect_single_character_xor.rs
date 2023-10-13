use super::single_byte_xor_cipher::{get_char_freq, single_bytes_xor_cipher, variation_distance};
use super::utils::{get_file_path, read_file};

fn detect_single_character_xor() -> String {
    let mut score = f32::MAX;
    let mut highest_string: String = String::from("");
    // let path = env::current_dir();
    // println!("The current directory is {}", path.unwrap().display());
    //
    let d = get_file_path("4.txt");
    println!("{}", d.display());

    let contents = read_file(d.to_str().unwrap());

    for line in contents.lines() {
        let (decoded_string,_) = single_bytes_xor_cipher(line);
        let freq = get_char_freq(&decoded_string);
        let temp_score = variation_distance(freq);
        if temp_score < score {
            score = temp_score;
            highest_string = decoded_string;
        }
        // println!("{}", decoded_string);
    }

    // println!("The decoded string: {}", highest_string);
    return highest_string;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_single_character_xor() {
        assert_eq!(
            detect_single_character_xor(),
            "Now that the party is jumping\n"
        );
    }
}
