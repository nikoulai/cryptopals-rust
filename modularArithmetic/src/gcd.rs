fn gcd(a: u64, b: u64) -> u64 {

	if b == 0 {
		return a;
	}
	else{
		return gcd(b, a % b);
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn  test_gcd(){
		assert_eq!(gcd(8, 12), 4);
        	assert_eq!(gcd(14, 28), 14);
        	assert_eq!(gcd(18, 35), 1);
        	assert_eq!(gcd(12, 8), 4);
        	assert_eq!(gcd(66528, 52920), 1512);
		}
	}
