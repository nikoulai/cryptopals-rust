// https://dev.to/skaunov/cryptopals-challenge-33-implement-diffie-hellman-3ma7
use crypto_bigint::{rand_core::OsRng, Checked, Encoding, NonZero, Random, U1536, U3072};
use sha3::{Digest, Sha3_256};

fn main() {
    let p = U1536::from_be_hex("ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff");
    let g = U1536::from(2u64);

    let a = U1536::random(&mut OsRng);
    let a_big = modexp(g, a, p);
    let b = U1536::random(&mut OsRng);
    let b_big = modexp(g, b, p);

    let s = modexp(b_big, a, p);

    println!("{s}");

    let mut hasher = Sha3_256::new();
    hasher.update(s.to_be_bytes());
    let result = hasher.finalize();
    println!("{result:?}");
}

fn modexp(base: U1536, exponent: U1536, modulus: U1536) -> U1536 {
    if modulus == U1536::ONE {
        return U1536::ZERO;
    }

    let modulus_ch = Checked::new(modulus);
    /* This algorithm is mostly based on Wikipedia
    listing, and the next line is to test the
    assertion they have. `unwrap`s below turned out
    to be much more useful during debuggig. */
    (modulus_ch - Checked::new(U1536::ONE)) * (modulus_ch - Checked::new(U1536::ONE));

    let mut result = Checked::new(U3072::ONE);

    let mut base = U1536::from(base);
    let mut base = base % NonZero::new(modulus).unwrap();

    let mut base = U3072::from_be_bytes(pad192(base));
    let mut base = Checked::new(base);

    let mut modulus = U3072::from_be_bytes(pad192(modulus));

    let mut exponent = exponent;
    while exponent > U1536::ZERO {
        if exponent % NonZero::new(U1536::from(2u64)).unwrap() == U1536::ONE {
            result = Checked::new((result * base).0.unwrap() % NonZero::new(modulus).unwrap());
        }
        exponent >>= 1;
        base = Checked::new((base * base).0.unwrap() % NonZero::new(modulus).unwrap());
    }
    /* It should be checked that excessive bytes are
    zero, but today we omit the check. They really
    should after `% p` */
    U1536::from_be_slice(result.0.unwrap().to_be_bytes()[192..].into())
}

fn pad192(uint_192: U1536) -> [u8; 384] {
    let mut res: [u8; 384] = [0; 384];
    res[192..].copy_from_slice(&uint_192.to_be_bytes());
    res
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_diffie() {
        println!("______-----_________----");
        main()
    }
}
