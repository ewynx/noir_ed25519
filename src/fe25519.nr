use dep::std;

// Radix-51 implementation for fe25519 arithmetic
struct BigInt256 {
  l: [u64; 5]
}

impl BigInt256 {

  pub fn zero() -> Self {
    let l = [0 as u64; 5];
    Self { 
      l
    }
  }

  // adds 2 field elements without reducing
  pub fn add(self: Self, other: Self) -> Self {
    let mut res = BigInt256::zero();
    for i in 0..5 {
      res.l[i] = self.l[i] + other.l[i];
    }
    res
  }

  // Source https://github.com/gtank/defcon25_crypto_village/blob/master/ed25519-gtank/internal/radix51/fe.go#L97
  pub fn sub(a: BigInt256, b: BigInt256) -> BigInt256 {
  
    let mut t = BigInt256 { l: b.l };
    let maskLow51Bits = ((1 as u64) << 51) - 1;

    t.l[1] += (t.l[0] >> 51);
    t.l[0] &= maskLow51Bits;
    t.l[2] += (t.l[1] >> 51);
    t.l[1] &= maskLow51Bits;
    t.l[3] += (t.l[2] >> 51);
    t.l[2] &= maskLow51Bits;
    t.l[4] += (t.l[3] >> 51);
    t.l[3] &= maskLow51Bits;
    t.l[0] += ((t.l[4] >> 51) * 19);
    t.l[4] &= maskLow51Bits;

    let mut res = BigInt256::zero();
    res.l[0] = (a.l[0] + 4503599627370458) - t.l[0];
    res.l[1] = (a.l[1] + 4503599627370494) - t.l[1];
    res.l[2] = (a.l[2] + 4503599627370494) - t.l[2];
    res.l[3] = (a.l[3] + 4503599627370494) - t.l[3];
    res.l[4] = (a.l[4] + 4503599627370494) - t.l[4];

    res
}


  pub fn reduce(self: &mut Self) -> &mut Self {
    let maskLow51Bits = ((1 as u64)<<51) - 1;
    self.l[1] += (self.l[0] >> 51);
    self.l[0] &= maskLow51Bits;
    self.l[2] += (self.l[1] >> 51);
    self.l[1] &= maskLow51Bits;
    self.l[3] += (self.l[2] >> 51);
    self.l[2] &= maskLow51Bits;
    self.l[4] += (self.l[3] >> 51);
    self.l[3] &= maskLow51Bits;
    self.l[0] += ((self.l[4] >> 51) * 19);
    self.l[4] &= maskLow51Bits;

    // Additional code for carry bit
    let mut c = (self.l[0] + 19) >> 51;
    c = (self.l[1] + c) >> 51;
    c = (self.l[2] + c) >> 51;
    c = (self.l[3] + c) >> 51;
    c = (self.l[4] + c) >> 51;

    self.l[0] += (19 * c);

    self.l[1] += (self.l[0] >> 51);
    self.l[0] &= maskLow51Bits;
    self.l[2] += (self.l[1] >> 51);
    self.l[1] &= maskLow51Bits;
    self.l[3] += (self.l[2] >> 51);
    self.l[2] &= maskLow51Bits;
    self.l[4] += (self.l[3] >> 51);
    self.l[3] &= maskLow51Bits;
    self.l[4] &= maskLow51Bits;
    self
  }

  // https://github.com/gtank/defcon25_crypto_village/blob/master/ed25519-gtank/internal/radix51/fe_mul.go
  // // multiplies and reduces
  // pub fn mult(self: Self, other: Self) -> Self {

  // }
}

pub fn equal(a: BigInt256, expected: [u64; 5]) {
    assert(a.l[0] == expected[0]);
    assert(a.l[1] == expected[1]);
    assert(a.l[2] == expected[2]);
    assert(a.l[3] == expected[3]);
    assert(a.l[4] == expected[4]);
}

#[test]
fn test_add() {
    let limbs_a = [1844259539195617, 215995683303882, 376629356723608, 1093146698323522, 1607438556832821];
    let limbs_b = [396269105830060, 2481219244355560, 2104589887631952, 2481219244355560, 1];
    let a = BigInt256 { l: limbs_a };
    let b = BigInt256 { l: limbs_b };
    let res = a.add(b);
    let expected = [2240528645025677, 2697214927659442, 2481219244355560, 3574365942679082, 1607438556832822];

    assert(expected[0] == res.l[0]);
    assert(expected[1] == res.l[1]);
    assert(expected[2] == res.l[2]);
    assert(expected[3] == res.l[3]);
    assert(expected[4] == res.l[4]);
}

#[test]
fn test_reduce() {
    let mut limbs_a = [0, 0, 0, 0, 0];
    let mut a = BigInt256 { l: limbs_a };
    let mut res = a.reduce();
    let mut expected = [0, 0, 0, 0, 0];
    equal(*res, expected);

    limbs_a = [4503599627370495, 1, 1, 1, 1];
    a = BigInt256 { l: limbs_a };
    res = a.reduce();
    expected = [2251799813685247, 2, 1, 1, 1];
    equal(*res, expected);

    limbs_a = [4503599627370495, 4503599627370495, 4503599627370495, 4503599627370495, 4503599627370495];
    a = BigInt256 { l: limbs_a };
    res = a.reduce();
    expected = [37, 1, 1, 1, 1];
    equal(*res, expected);

    limbs_a = [9223372036854775807, 0, 0, 0, 0];
    a = BigInt256 { l: limbs_a };
    res = a.reduce();
    expected = [2251799813685247, 4095, 0, 0, 0];
    equal(*res, expected);
}

#[test]
fn test_subtraction() {
    let mut limbs_a = [2, 2, 2, 2, 2];
    let mut limbs_b = [1, 1, 1, 1, 1];
    let mut a = BigInt256 { l: limbs_a };
    let mut b = BigInt256 { l: limbs_b };
    let mut a_min_b = a.sub(b);
    a_min_b = *a_min_b.reduce();
    equal(a_min_b, [1, 1, 1, 1, 1]);

    limbs_a = [1844259539195617, 215995683303882, 376629356723608, 1093146698323522, 1607438556832821];
    limbs_b = [396269105830060, 2481219244355560, 2104589887631952, 2481219244355560, 1];
    a = BigInt256 { l: limbs_a };
    b = BigInt256 { l: limbs_b };
    a_min_b = a.sub(b);
    a_min_b = *a_min_b.reduce();
    equal(
        a_min_b,
        [1447990433365557, 2238376066318818, 523839282776902, 863727267653209, 1607438556832819]
    );
}
