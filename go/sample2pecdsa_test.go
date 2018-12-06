package main

import (
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/btcsuite/btcd/btcec"
)

func Test2PECDSA(t *testing.T) {
	// Alice
	xa := Rnd(n)     // xa
	Pa := Mul(xa, G) // Pa
	ka := Rnd(n)     // ka
	Ra := Mul(ka, G) // Ra
	t.Log("Alice :")
	t.Logf("Pa : %x", Pa.Compressed())
	t.Logf("Ra : %x", Ra.Compressed())
	// Paillier pub and pri key
	pub, pri, err := KeyGeneration(2048)
	if err != nil {
		t.Errorf("error : %+v", err)
		return
	}
	// Bob
	xb := Rnd(n)     // xb
	Pb := Mul(xb, G) // Pb
	kb := Rnd(n)     // kb
	Rb := Mul(kb, G) // Rb
	t.Log("Bob :")
	t.Logf("Pb : %x", Pb.Compressed())
	t.Logf("Rb : %x", Rb.Compressed())
	// share public key
	P := Mul(xa, Pb)
	if Rnd(big.NewInt(255)).Bit(0) == 0 {
		P = Mul(xb, Pa)
	}
	// random key
	R := Mul(ka, Rb)
	if Rnd(big.NewInt(255)).Bit(0) == 0 {
		R = Mul(kb, Ra)
	}
	// x coordinate of random key
	r := R.X
	// encrypt xa to ckey
	ckey, err := pub.Encryption(xa)
	if err != nil {
		t.Errorf("error : %+v", err)
		return
	}
	// message : m
	m := make([]byte, 32)
	rand.Read(m)
	hash := H(m)
	// message hash : m'
	md := new(big.Int).SetBytes(hash)
	// random ρ
	rho := Rnd(n)
	// 1 / kb
	kbinv := new(big.Int).ModInverse(kb, n)
	// c1 = m' / ka + ρn
	c1, err := pub.Encryption(new(big.Int).Add(
		new(big.Int).Mul(kbinv, md),
		new(big.Int).Mul(rho, n)))
	if err != nil {
		t.Errorf("error : %+v", err)
		return
	}
	// c2 = ckey ^ {xb * r / kb }
	c2 := pub.Exp(ckey, new(big.Int).Mul(new(big.Int).Mul(xb, r), kbinv))
	// c3 = c1 * c2
	c3 := pub.Mul(c1, c2)
	// s' = (m' + rxaxb) / kb + ρn
	sd, err := pri.Decryption(c3)
	if err != nil {
		t.Errorf("error : %+v", err)
		return
	}
	// 1 / ka
	kainv := new(big.Int).ModInverse(ka, n)
	// s = (m' + rxaxb) / kakb
	s := new(big.Int).Mod(new(big.Int).Mul(sd, kainv), n)
	// s = min{s,n-s mod n}
	s = min(s, n)
	// verify
	result := Verify(P, m, r, s)
	if !result {
		t.Errorf("Verify error : %v", result)
		return
	}
	t.Logf("result : %v", result)
	// btcec.ParseDERSignature
	sig, err := btcec.ParseDERSignature(DER(r, s), btcec.S256())
	if err != nil {
		t.Errorf("%v", err)
		return
	}
	// btcec.ParsePubKey
	pubkey, err := btcec.ParsePubKey(P.Compressed(), btcec.S256())
	if err != nil {
		t.Errorf("%v", err)
		return
	}
	// btcec.Verify
	result = sig.Verify(hash, pubkey)
	if !result {
		t.Errorf("btcec.Verify error : %v", result)
		return
	}
	t.Logf("result : %v", result)
}

func min(s, n *big.Int) *big.Int {
	sd := new(big.Int).Mod(new(big.Int).Sub(n, s), n)
	if s.Cmp(sd) < 0 {
		return s
	}
	return sd
}
