package main

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

// ZERO is 0
var ZERO = big.NewInt(0)

// ONE is 1 of *big.Int .
var ONE = big.NewInt(1)

// Rnd returns a random number less than n
func Rnd(n *big.Int) *big.Int {
	tmp := make([]byte, len(n.Bytes()))
	rand.Read(tmp)
	return new(big.Int).Mod(new(big.Int).SetBytes(tmp), n)
}

// greatest common divisor
func gcd(a, b *big.Int) *big.Int {
	if a.Cmp(b) < 0 {
		return gcd(b, a)
	}
	for b.Cmp(big.NewInt(0)) != 0 {
		r := new(big.Int).Mod(a, b)
		a = b
		b = r
	}
	return a
}

// least common multiple
func lcm(a, b *big.Int) *big.Int {
	return new(big.Int).Div(new(big.Int).Mul(a, b), gcd(a, b))
}

// PublicKey is a pailliar public key.
type PublicKey struct {
	n  *big.Int // n
	g  *big.Int // g
	n2 *big.Int // n^2
}

// Encryption returns an encrypted data.
func (pub *PublicKey) Encryption(m *big.Int) (*big.Int, error) {
	// plaintext m < n
	if m.Cmp(ZERO) < 0 || m.Cmp(pub.n) >= 0 {
		return nil, fmt.Errorf("m is out of range")
	}
	// select a random r < n
	r := new(big.Int)
	for {
		r = Rnd(pub.n)
		if gcd(r, pub.n).Cmp(ONE) == 0 {
			break
		}
	}
	// ciphertext c = g^m * r^n mod n^2
	c := new(big.Int).Mod(new(big.Int).Mul(
		new(big.Int).Exp(pub.g, m, pub.n2),
		new(big.Int).Exp(r, pub.n, pub.n2)), pub.n2)
	return c, nil
}

// Mul returns c1 * c2 mod n2
func (pub *PublicKey) Mul(c1, c2 *big.Int) *big.Int {
	// c1 * c2 -> m1 + m2
	return new(big.Int).Mod(new(big.Int).Mul(c1, c2), pub.n2)
}

// Exp returns c ^ m mod n2
func (pub *PublicKey) Exp(c, m *big.Int) *big.Int {
	// c ^ m2 -> m1 * m2
	return new(big.Int).Exp(c, m, pub.n2)
}

// PrivateKey is a pailliar private key.
type PrivateKey struct {
	lam *big.Int // λ = lcm(p-1,q-1)
	mu  *big.Int // μ = 1 / L(g^λ mod n^2)
	n   *big.Int // n = p * q
	n2  *big.Int // n^2
}

// Decryption returns the decrypted data.
func (pri *PrivateKey) Decryption(c *big.Int) (*big.Int, error) {
	// ciphertext c < n 2
	if c.Cmp(ZERO) <= 0 || c.Cmp(pri.n2) >= 0 {
		return nil, fmt.Errorf("c is out of range")
	}
	// plaintext m = L(c^λ mod n^2) / L(g^λ mod n^2) mod n
	//             = L(c^λ mod n^2) * μ mod n
	m := new(big.Int).Mod(new(big.Int).Mul(
		L(new(big.Int).Exp(c, pri.lam, pri.n2), pri.n), pri.mu), pri.n)
	return m, nil
}

// L returns (x - 1) / n .
func L(x, n *big.Int) *big.Int {
	if new(big.Int).Mod(new(big.Int).Sub(x, ONE), n).Cmp(ZERO) != 0 {
		return nil
	}
	return new(big.Int).Div(new(big.Int).Sub(x, ONE), n)
}

// KeyGeneration returns a public and a private keys of pailliar cipher.
func KeyGeneration(bits int) (*PublicKey, *PrivateKey, error) {
	// p and q are large primes
	p := probablyPrime(bits / 2)
	q := probablyPrime(bits / 2)
	if p.Cmp(q) == 0 {
		return KeyGeneration(bits)
	}
	// n = p * q
	n := new(big.Int).Mul(p, q)
	// n^2 = n * n
	n2 := new(big.Int).Mul(n, n)
	// λ = lcm(p-1,q-1)
	lam := lcm(new(big.Int).Sub(p, ONE), new(big.Int).Sub(q, ONE))
	// randomly select a base g
	g := new(big.Int)
	// μ = 1 / L(g^λ mod n^2)
	mu := new(big.Int)
	for {
		g = Rnd(n2)
		if gcd(g, n2).Cmp(ONE) != 0 {
			continue
		}
		mu = L(new(big.Int).Exp(g, lam, n2), n)
		// gcd(L(g^λ mod n^2 ), n) = 1
		if gcd(mu, n).Cmp(ONE) != 0 {
			continue
		}
		mu = new(big.Int).ModInverse(mu, n)
		break
	}
	// public key
	pub := &PublicKey{n: n, g: g, n2: n2}
	// private key
	pri := &PrivateKey{lam: lam, mu: mu, n: n, n2: n2}
	return pub, pri, nil
}

func probablyPrime(bits int) *big.Int {
	max := new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(bits)), nil)
	p := big.NewInt(0)
	cnt := 0
	for !isProbablyPrime(p) {
		p = Rnd(max)
		for p.BitLen() != bits {
			p = Rnd(max)
		}
		cnt++
	}
	return p
}

func isProbablyPrime(n *big.Int) bool {
	ONE := big.NewInt(1)
	TWO := big.NewInt(2)
	if n.Cmp(ONE) <= 0 {
		return false
	}
	// if n == 2 then prime
	if n.Cmp(TWO) == 0 {
		return true
	}
	// even check
	if n.Bit(0) == 0 {
		return false
	}
	// n-1 = 2^s * d
	d := new(big.Int).Sub(n, ONE)
	s := big.NewInt(0)
	for d.Bit(0) == 0 {
		d.Rsh(d, 1)
		s.Add(s, ONE)
	}
	k := 512
	nm1 := new(big.Int).Sub(n, ONE)
	for i := 0; i < k; i++ {
		// a in [1,n-1]
		a := Rnd(nm1)
		a.Add(a, ONE)
		// a^{d} mod n == 1
		t := new(big.Int).Exp(a, d, n)
		if t.Cmp(ONE) == 0 {
			continue
		}
		flg := false
		// r in [0,s-1] , a^{2^rd} mod n == -1
		// a^{2^0 * d} , a^{2^1 * d} , a^{2^2 * d} , .... , a^{2^(s-1) * d}
		for r := big.NewInt(0); r.Cmp(s) < 0; r.Add(r, ONE) {
			if t.Cmp(nm1) == 0 {
				flg = true
				break
			}
			t.Exp(t, TWO, n)
		}
		if !flg {
			return false
		}
	}
	return true
}
