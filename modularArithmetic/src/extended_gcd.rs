fn extended_gcd(r0: i64, r1: i64) -> (i64, i64, i64) {

	let mut s0: i64 = 1;
	let mut s1: i64 = 0;
	let mut t0: i64 = 0;
	let mut t1: i64 = 1;
	
	return extended_gcd_help(r0, r1, s0, s1, t0, t1)
}
fn extended_gcd_help(r0: i64, r1: i64, s0: i64, s1: i64, t0: i64, t1: i64) -> (i64, i64, i64){
	if r1 != 0 {
		let q = r0 / r1;
		let r = r0 % r1;
		let s = s0 - q * s1;
		let t = t0 - q * t1;
		
		return extended_gcd_help(r1, r, s1, s, t1, t)
	}
	else {
		return (r0, s0, t0)
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn  test_extended_gcd(){
		assert_eq!(extended_gcd(12, 5), (1, -2, 5));
		assert_eq!(extended_gcd(26513, 32321), (1,10245,-8404));
        	// assert_eq!(extended_gcd(14, 28), 14);
        	// assert_eq!(extended_gcd(18, 35), 1);
        	// assert_eq!(extended_gcd(12, 8), 4);
        	// assert_eq!(extended_gcd(66528, 52920), 1512);
		}
	}