use super::ctr::ctr_to_bytes;
use set1::break_repeating_xor::break_repeating_key_bytes;
use set1::repeating_key_xor::repeating_key_xor;
use set1::utils::{decode_b64_to_bytes, hex_to_bytes};
use std::str::{from_utf8, from_utf8_unchecked};

const key: &str = "YELLOW SUBMARINE";
const b64_strings: [&str; 40] = [
    "SSBoYXZlIG1ldCB0aGVtIGF0IGNsb3NlIG9mIGRheQ==",
    "Q29taW5nIHdpdGggdml2aWQgZmFjZXM=",
    "RnJvbSBjb3VudGVyIG9yIGRlc2sgYW1vbmcgZ3JleQ==",
    "RWlnaHRlZW50aC1jZW50dXJ5IGhvdXNlcy4=",
    "SSBoYXZlIHBhc3NlZCB3aXRoIGEgbm9kIG9mIHRoZSBoZWFk",
    "T3IgcG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==",
    "T3IgaGF2ZSBsaW5nZXJlZCBhd2hpbGUgYW5kIHNhaWQ=",
    "UG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==",
    "QW5kIHRob3VnaHQgYmVmb3JlIEkgaGFkIGRvbmU=",
    "T2YgYSBtb2NraW5nIHRhbGUgb3IgYSBnaWJl",
    "VG8gcGxlYXNlIGEgY29tcGFuaW9u",
    "QXJvdW5kIHRoZSBmaXJlIGF0IHRoZSBjbHViLA==",
    "QmVpbmcgY2VydGFpbiB0aGF0IHRoZXkgYW5kIEk=",
    "QnV0IGxpdmVkIHdoZXJlIG1vdGxleSBpcyB3b3JuOg==",
    "QWxsIGNoYW5nZWQsIGNoYW5nZWQgdXR0ZXJseTo=",
    "QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=",
    "VGhhdCB3b21hbidzIGRheXMgd2VyZSBzcGVudA==",
    "SW4gaWdub3JhbnQgZ29vZCB3aWxsLA==",
    "SGVyIG5pZ2h0cyBpbiBhcmd1bWVudA==",
    "VW50aWwgaGVyIHZvaWNlIGdyZXcgc2hyaWxsLg==",
    "V2hhdCB2b2ljZSBtb3JlIHN3ZWV0IHRoYW4gaGVycw==",
    "V2hlbiB5b3VuZyBhbmQgYmVhdXRpZnVsLA==",
    "U2hlIHJvZGUgdG8gaGFycmllcnM/",
    "VGhpcyBtYW4gaGFkIGtlcHQgYSBzY2hvb2w=",
    "QW5kIHJvZGUgb3VyIHdpbmdlZCBob3JzZS4=",
    "VGhpcyBvdGhlciBoaXMgaGVscGVyIGFuZCBmcmllbmQ=",
    "V2FzIGNvbWluZyBpbnRvIGhpcyBmb3JjZTs=",
    "SGUgbWlnaHQgaGF2ZSB3b24gZmFtZSBpbiB0aGUgZW5kLA==",
    "U28gc2Vuc2l0aXZlIGhpcyBuYXR1cmUgc2VlbWVkLA==",
    "U28gZGFyaW5nIGFuZCBzd2VldCBoaXMgdGhvdWdodC4=",
    "VGhpcyBvdGhlciBtYW4gSSBoYWQgZHJlYW1lZA==",
    "QSBkcnVua2VuLCB2YWluLWdsb3Jpb3VzIGxvdXQu",
    "SGUgaGFkIGRvbmUgbW9zdCBiaXR0ZXIgd3Jvbmc=",
    "VG8gc29tZSB3aG8gYXJlIG5lYXIgbXkgaGVhcnQs",
    "WWV0IEkgbnVtYmVyIGhpbSBpbiB0aGUgc29uZzs=",
    "SGUsIHRvbywgaGFzIHJlc2lnbmVkIGhpcyBwYXJ0",
    "SW4gdGhlIGNhc3VhbCBjb21lZHk7",
    "SGUsIHRvbywgaGFzIGJlZW4gY2hhbmdlZCBpbiBoaXMgdHVybiw=",
    "VHJhbnNmb3JtZWQgdXR0ZXJseTo=",
    "QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=",
];

// Most common bigrams (in order) th, he, in, en, nt, re, er, an, ti, es, on, at, se, nd, or, ar, al, te, co, de, to, ra, et, ed, it, sa, em, ro.
// Most common trigrams (in order) the, and, tha, ent, ing, ion, tio, for, nde, has, nce, edt, tis, oft, sth, men.
//todo come back

pub unsafe fn break_fix_nonce() {
    let decoded_strings: Vec<Vec<u8>> = b64_strings
        .map(|s| decode_b64_to_bytes(s).to_owned())
        .into_iter()
        .collect();

    println!("------");
    let ciphertexts: Vec<Vec<u8>> = decoded_strings
        .iter()
        .map(|p| ctr_to_bytes(p, key.as_bytes(), 0))
        .collect();

    let min_cipher_len =
        ciphertexts.iter().fold(
            u8::MAX as usize,
            |acc, x| {
                if x.len() < acc {
                    x.len()
                } else {
                    acc
                }
            },
        );
    // println!("@@@@@@{:?} {}", ciphertexts, min_cipher_len);

    // for inner_vec in &ciphertexts {
    // Iterate over the inner vector and print the length
    // for element in inner_vec {
    //     print!("{} ", element);
    // }
    // println!(" - Length: {}", inner_vec.len());
    // }

    let block_size = 16;
    let first_block: Vec<u8> = ciphertexts
        .iter()
        .flat_map(|inner_vec| {
            inner_vec
                .iter()
                .take(block_size)
                .cloned()
                .collect::<Vec<_>>()
        })
        .collect::<Vec<u8>>();
    // println!("####### len{:?}", &first_block.len());
    let possible_keys = break_repeating_key_bytes(first_block.clone(), block_size);
    println!("Possible keys: {:?}", possible_keys);
    for possible_key in possible_keys {
        let possible_key_string = from_utf8_unchecked(&possible_key);
        println!("-------------{:?}", possible_key);

        println!(
            "{:?}",
            from_utf8_unchecked(
                hex_to_bytes(
                    repeating_key_xor(
                        &possible_key_string,
                        from_utf8_unchecked(first_block.as_slice()),
                    )
                    .as_str()
                )
                .as_slice()
            )
        );
    }

    // println!("{:?}", from_utf8_unchecked(&*possible_key));
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    pub fn test_break_fix_nonce() {
        unsafe {
            break_fix_nonce();
        }
    }
}
