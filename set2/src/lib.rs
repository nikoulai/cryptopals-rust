#![allow(dead_code)]
#![allow(warnings)]
pub mod byte_at_a_time_ecb_decryption;
pub mod cbc_mode;
pub mod ecb_cbc_detection_oracle;
pub mod ecb_cut_paste;
pub mod pkcs7_padding;

pub mod byte_at_a_time_ecb_harder;
mod cbc_bitflipping;
