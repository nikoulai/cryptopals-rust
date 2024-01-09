// use num_bigint::{BigUint, ToBigUint};
// use num_traits::{One, Zero};
//
// pub fn modexp(base: BigUint, exponent: BigUint, modulus: BigUint) -> BigUint {
//     if modulus == One::one() {
//         return One::one();
//     }
//     let mut c: BigUint = One::one();
//
//     for e_prime in 0..(exponent. - 1) {
//         c = (c * base.clone()) % modulus.clone();
//     }
//
//     return c;
// }
//
// #[cfg(test)]
// mod tests {
//     use super::*;
//     use std::num;
//
//     #[test]
//     fn test_modexp() {
//         let base = BigUint::from(5u32);
//         let exponent = BigUint::from(3u32);
//         let modulus = BigUint::from(13u32);
//         let result = modexp(base.clone(), exponent.clone(), modulus.clone());
//         let expected = BigUint::from(8u32);
//
//         assert_eq!(result, expected);
//     }
//
//     // Add more test cases as needed
// }
