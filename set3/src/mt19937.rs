struct MT19937 {
    w: u32,
    n: usize,
    m: usize,
    r: u128,
    a: u128,
    u: u128,
    d: u128,
    s: u128,
    b: u128,
    t: u128,
    c: u128,
    l: u128,
    f: u128,

    MT: Vec<u32>,
    index: usize,
    lower_mask: u32,
    upper_mask: u32,
}

impl MT19937 {
    fn new() -> Self {
        let _n = 624;
        let _r = 31;
        let _lower_mask = (1 << _r) - 1;
        MT19937 {
            w: 32,
            n: _n,
            m: 397,
            r: _r,
            a: 0x9908B0DF,
            u: 11,
            d: 0xFFFFFFFF,
            s: 7,
            b: 0x9D2C5680,
            t: 15,
            c: 0xEFC60000,
            l: 18,
            f: 1812433253,

            MT: vec![0; _n],
            index: (_r + 1) as usize,

            lower_mask: _lower_mask,
            upper_mask: (!_lower_mask) & 0xFFFFFFFF,
        }
    }
    fn seed_mt(&mut self, seed: u32) {
        self.index = self.n;
        //     MT[0] := seed
        let _ = std::mem::replace(&mut self.MT[0], seed);

        for i in 1..self.n {
            // MT[i] := lowest w bits of (f * (MT[i-1] xor (MT[i-1] >> (w-2))) + i)
            let temp_calc = self.lower_mask as u128
                & (self.f
                    * (*self.MT.get(i - 1).unwrap() as u128
                        ^ (self.MT.get(i - 1).unwrap() >> (self.w - 2)) as u128)
                    + 1);

            let _ = std::mem::replace(&mut self.MT[i], temp_calc as u32);
        }
    }

    fn extract_number(&mut self) -> u32 {
        if self.index >= self.n {
            if self.index > self.n {
                panic!("Generator was never seeded");
            }
            self.twist()
        }

        let mut y: u32 = self.MT[self.index];

        y = y ^ ((y >> self.u) & self.d as u32);
        y = y ^ ((y << self.s) & self.b as u32);
        y = y ^ ((y << self.t) & self.c as u32);
        y = y ^ (y >> self.l);

        self.index = self.index + 1;
        return self.lower_mask & (y);
    }

    fn twist(&mut self) {
        for i in 0..self.n {
            let x: u32 = (self.MT.get(i).unwrap() & self.upper_mask) as u32
                | (self.MT.get((i + 1) % self.n).unwrap() & self.lower_mask) as u32;

            let mut xA: u32 = x >> 1;
            if (x % 2) != 0 {
                // lowest bit of x is 1
                xA = xA ^ self.a as u32;
            }
            // MT[i] := MT[(i + m) mod n] xor xA
            let temp_cal = *self.MT.get((i + self.m) % self.n).unwrap() ^ xA as u32;
            let _ = std::mem::replace(&mut self.MT[i], temp_cal);
        }
        self.index = 0;
    }
}
// strust MT19937 {
//  w: u128 = 32;

// That is, the binary number of r 1's
// const upper_mask: u128 =
// }
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_seed_and_extract_number() {
        // Test that seed initializes the state and extract_number produces expected values
        let seed_value = 123;
        let mut mt = MT19937::new();
        mt.seed_mt(seed_value);

        // The first few values generated with the given seed
        assert_eq!(mt.extract_number(), 3501100022);
        assert_eq!(mt.extract_number(), 2985639871);
        assert_eq!(mt.extract_number(), 3477476795);
    }

    #[test]
    fn test_twist() {
        // Test that twist updates the state, and extract_number produces expected values afterward
        let seed_value = 456;
        let mut mt = MT19937::new();

        mt.seed_mt(seed_value);
        // Save the state before the twist
        let state_before = mt.MT.clone();

        // Generate a few numbers before the twist
        mt.extract_number();
        mt.extract_number();
        mt.extract_number();

        // Perform the twist
        mt.twist();

        // Ensure that the state has changed
        assert_ne!(mt.MT, state_before);

        // Generate numbers after the twist and ensure they are different from before
        assert_ne!(mt.extract_number(), state_before[0]);
        assert_ne!(mt.extract_number(), state_before[1]);
        assert_ne!(mt.extract_number(), state_before[2]);
    }
}
