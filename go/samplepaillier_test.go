package main

import (
	"math/big"
	"testing"
)

func TestPailliar(t *testing.T) {
	pub, pri, err := KeyGeneration(1024)
	if err != nil {
		t.Errorf("error %v", err)
		return
	}
	m1 := Rnd(big.NewInt(1000000))
	m2 := Rnd(big.NewInt(1000000))
	t.Logf("m1 : %d", m1)
	t.Logf("m2 : %d", m2)
	c1, err := pub.Encryption(m1)
	if err != nil {
		t.Errorf("error %v", err)
		return
	}
	c2, err := pub.Encryption(m2)
	if err != nil {
		t.Errorf("error %v", err)
		return
	}
	t.Logf("c1 : %d", c1)
	t.Logf("c2 : %d", c2)
	x1, err := pri.Decryption(c1)
	if err != nil {
		t.Errorf("error %v", err)
		return
	}
	x2, err := pri.Decryption(c2)
	if err != nil {
		t.Errorf("error %v", err)
		return
	}
	t.Logf("x1 : %d", x1)
	t.Logf("x2 : %d", x2)
	if m1.Cmp(x1) != 0 {
		t.Errorf("m1 != x1 : %d != %d", m1, x1)
		return
	}
	if m2.Cmp(x2) != 0 {
		t.Errorf("m2 != x2 : %d != %d", m2, x2)
		return
	}
	c3 := pub.Mul(c1, c2)
	x3, err := pri.Decryption(c3)
	if err != nil {
		t.Errorf("error %v", err)
		return
	}
	t.Logf("c3 : %d", c3)
	t.Logf("x3 : %d", x3)
	if x3.Cmp(new(big.Int).Add(m1, m2)) != 0 {
		t.Errorf("m1 + m2 != x3 : %d + %d != %d", m1, m2, x3)
		return
	}
	c4 := pub.Exp(c1, m2)
	x4, err := pri.Decryption(c4)
	if err != nil {
		t.Errorf("error %v", err)
		return
	}
	t.Logf("c4 : %d", c4)
	t.Logf("x4 : %d", x4)
	if x4.Cmp(new(big.Int).Mul(m1, m2)) != 0 {
		t.Errorf("m1 * m2 != x4 : %d * %d != %d", m1, m2, x4)
		return
	}
}

func TestGCD(t *testing.T) {
	a := big.NewInt(1071)
	b := big.NewInt(1029)
	c := gcd(a, b)
	t.Logf("gcd(%d,%d)=%d", a, b, c)
	if big.NewInt(21).Cmp(c) != 0 {
		t.Errorf("illegal gcd(%d,%d)=%d", a, b, c)
		return
	}
	a = big.NewInt(221)
	b = big.NewInt(153)
	c = gcd(a, b)
	t.Logf("gcd(%d,%d)=%d", a, b, c)
	if big.NewInt(17).Cmp(c) != 0 {
		t.Errorf("illegal gcd(%d,%d)=%d", a, b, c)
		return
	}
	a = big.NewInt(144)
	b = big.NewInt(89)
	c = gcd(a, b)
	t.Logf("gcd(%d,%d)=%d", a, b, c)
	if big.NewInt(1).Cmp(c) != 0 {
		t.Errorf("illegal gcd(%d,%d)=%d", a, b, c)
		return
	}
}

func TestProbablyPrime(t *testing.T) {
	// http: //homepages.math.uic.edu/~leon/mcs425-s08/handouts/Rabin-Miller-Examples.pdf
	d := map[int64]bool{252601: false, 3057601: false, 104717: true, 577757: true, 101089: true, 280001: true, 95721889: false}
	for k, v := range d {
		r := isProbablyPrime(big.NewInt(k))
		if r != v {
			t.Errorf("error %8d %5v %5v", k, v, r)
			return
		}
		t.Logf("%8d %5v %5v", k, v, r)
	}
}
