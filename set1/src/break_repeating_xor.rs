use super::repeating_key_xor::repeating_key_xor;
use super::single_byte_xor_cipher::single_bytes_xor_cipher;
use super::utils::{decode_b64_to_bytes, read_file, xor_vec_bytes};
use crate::utils::{get_file_path, hex_to_bytes};

use std::str::from_utf8;
#[derive(Debug, PartialEq, Eq, PartialOrd)]
struct Item {
    value: u128,
    index: usize,
}

impl Ord for Item {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.value.cmp(&other.value)
    }
}
impl Item {
    // Adding a new associated function for creating new instances of `Item`
    fn new(value: u128, index: usize) -> Self {
        Item { value, index }
    }
}

pub fn hamming_distance_bytes(bytes1: &Vec<u8>, bytes2: &Vec<u8>) -> u128 {
    xor_vec_bytes(bytes1, bytes2)
        .iter()
        .fold(0, |acc, byte| ((byte.count_ones()) as u128) + acc)
}
pub fn hamming_distance(str1: &str, str2: &str) -> u128 {
    let bytes1 = str1.as_bytes().to_vec();
    let bytes2 = str2.as_bytes().to_vec();

    hamming_distance_bytes(&bytes1, &bytes2)
}

// fn transpose_blocks(content: &Vec<u8>, block_size: usize) -> Vec<Vec<u8>> {
//     let blocks_capacity = content.len() / block_size;
//     // let mut blocks_vector = vec![Vec::with_capacity(blocks_capacity),block_size];
//     let blocks_count = (content.len() + block_size - 1) / block_size;
//     let mut blocks_vector: Vec<Vec<u8>> = vec![Vec::with_capacity(blocks_capacity); block_size];
//
//     for (pos, e) in content.iter().enumerate() {
//         blocks_vector
//             .get_mut(pos / block_size)
//             .unwrap()
//             .push(e.to_owned());
//     }
//
//     return blocks_vector;
// }
fn transpose_blocks(content: &Vec<u8>, block_size: usize) -> Vec<Vec<u8>> {
    let blocks_count = (content.len() + block_size - 1) / block_size;
    let mut blocks_vector: Vec<Vec<u8>> = vec![Vec::with_capacity(blocks_count); block_size];

    for (pos, e) in content.iter().enumerate() {
        blocks_vector[pos % block_size].push(*e);
    }

    blocks_vector
}

pub fn break_repeating_key() {
    let contents = read_file(get_file_path("6.txt").to_str().unwrap());
    // let lines = contents
    //                                .lines()
    //                                .map(|line| general_purpose::STANDARD.decode(line).unwrap()).collect::<Vec<Vec<u8>>>();
    // let first_lines = lines.iter().take(4).collect::<Vec<&Vec<u8>>>();
    // println!("{:?}", first_lines);
    // let top_three_sizes: Vec<(u8,u8)> =  Vec::with_capacity(3);
    let content = contents.replace('\n', "");
    let content_bytes = decode_b64_to_bytes(content.as_str());
    let possible_keys = break_repeating_key_bytes(content_bytes.clone(), 0);
    for possible_key in possible_keys {
        let possible_key_string = from_utf8(&possible_key).unwrap();
        println!("-------------{:?}", possible_key);

        println!(
            "{:?}",
            from_utf8(
                hex_to_bytes(
                    repeating_key_xor(
                        &possible_key_string,
                        from_utf8(content_bytes.as_slice()).unwrap(),
                    )
                    .as_str()
                )
                .as_slice()
            )
        );
    }
}
pub fn break_repeating_key_bytes(content_bytes: Vec<u8>, key_size: usize) -> Vec<Vec<u8>> {
    let mut hamming_distances = Vec::with_capacity(40);
    let mut possible_key_sizes = 2..41;
    if key_size != 0 {
        println!("^^^^^^");
        possible_key_sizes = key_size..(key_size + 1);
    }
    println!("^^^^^^{:?}", possible_key_sizes);
    for KEYSIZE in possible_key_sizes {
        let number_of_blocks = content_bytes.len() / KEYSIZE - 1;
        let mut res = 0;
        // for i in (0..number_of_blocks/2) {
        for i in (0..number_of_blocks / 4).step_by(2) {
            // println!(
            //     "The step is {}, {}, {}, {} , {}",
            //     i,
            //     (i * KEYSIZE),
            //     ((i + 1) * KEYSIZE),
            //     (i + 1) * KEYSIZE,
            //     (i + 2) * KEYSIZE
            // );
            let first_slice = &content_bytes[(i * KEYSIZE)..((i + 1) * KEYSIZE)].to_vec();
            let second_slice = &content_bytes[((i + 1) * KEYSIZE)..((i + 2) * KEYSIZE)].to_vec();
            // let first_slice = &content_bytes[0..KEYSIZE].to_vec();
            // = &content_bytes[KEYSIZE..2*KEYSIZE].to_vec();
            let ham_distance_normalized_1 =
                hamming_distance_bytes(first_slice, second_slice) / KEYSIZE as u128;

            res += ham_distance_normalized_1;
        }
        // let third_slice = &content_bytes[2*KEYSIZE..3*KEYSIZE].to_vec();
        // let fourth_slice = &content_bytes[3*KEYSIZE..4*KEYSIZE].to_vec();

        // let ham_distance_normalized_3 =  hamming_distance_bytes(first_slice,third_slice)/ KEYSIZE as u128;
        // let ham_distance_normalized_4 =  hamming_distance_bytes(second_slice,fourth_slice)/ KEYSIZE as u128;
        // let res = (ham_distance_normalized_1 + ham_distance_normalized_2 + ham_distance_normalized_3 + ham_distance_normalized_4);
        // println!("{:?}", ham_distance_normalized_1 / (KEYSIZE as u128));
        println!("resresresresres: {:?} KEYSIZE {}", res, KEYSIZE);
        hamming_distances.push(Item::new(res, KEYSIZE));
    }

    hamming_distances.sort_by(|a, b| b.cmp(a));
    let mut higher_scores = Vec::new();

    // println!("{:?} {:?}", first_slice, second_slice);
    println!("The heap: {:?}", hamming_distances);
    let mut top_distances = hamming_distances
        .iter()
        .rev()
        .map(|x| x.index.clone())
        .collect::<Vec<usize>>()
        .into_iter()
        .take(4)
        .collect::<Vec<usize>>();
    higher_scores.append(&mut top_distances);

    // higher_scores.push(hamming_distances.pop().unwrap_or(Vec::new()).index);
    // higher_scores.push(hamming_distances.pop().unwrap().index);
    // higher_scores.push(hamming_distances.pop().unwrap().index);
    // higher_scores.push(hamming_distances.pop().unwrap().index);
    // higher_scores.push(hamming_distances.pop().unwrap().index);
    // higher_scores.push(hamming_distances.pop().unwrap().index);
    // higher_scores.push(hamming_distances.pop().unwrap().index);
    // higher_scores.push(hamming_distances.pop().unwrap().index);
    // higher_scores.push(hamming_distances.pop().unwrap().index);
    // higher_scores.push(hamming_distances.pop().unwrap().index);
    println!("{:?}", higher_scores);

    let mut possible_keys: Vec<Vec<u8>> = Vec::new();
    for i in higher_scores {
        let trasposed_blocks = transpose_blocks(&content_bytes, i);
        let mut possible_key: Vec<u8> = Vec::new();
        println!("Transposed blocks number is {}", &trasposed_blocks.len());
        for blocks in trasposed_blocks {
            let hex_string = hex::encode(&blocks);
            let (_, char) = single_bytes_xor_cipher(hex_string.as_str());
            possible_key.push(char);
        }
        possible_keys.push(possible_key.clone());
    }
    return possible_keys;
}

#[cfg(test)]
mod tests {
    use crate::break_repeating_xor::{break_repeating_key, hamming_distance, transpose_blocks};

    #[test]
    pub fn test_hamming_distance() {
        assert_eq!(hamming_distance(&"this is a test", &"wokka wokka!!!"), 37);
    }

    #[test]
    pub fn test_break_repeating_key() {
        assert_eq!(break_repeating_key(), ());
    }

    #[test]
    fn test_transpose_blocks() {
        let mut content = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let block_size = 4;
        let mut transposed = transpose_blocks(&content, block_size);

        assert_eq!(
            transposed,
            vec![
                vec![1, 5, 9],
                vec![2, 6, 10],
                vec![3, 7, 11],
                vec![4, 8, 12]
            ]
        );

        content = vec![1, 2, 3, 4, 5, 6, 7, 8, 9];
        transposed = transpose_blocks(&content, block_size);

        assert_eq!(
            transposed,
            vec![vec![1, 5, 9], vec![2, 6], vec![3, 7], vec![4, 8]]
        );
    }
}
