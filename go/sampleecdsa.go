package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"math/big"
)

// H returns the double hash of message.
func H(m []byte) []byte {
	hash := sha256.Sum256(m)
	hash = sha256.Sum256(hash[:])
	return hash[:]
}

// 2.3.2.  Bit String to Integer
// https://tools.ietf.org/html/rfc6979#section-2.3.2
func bits2int(m []byte) *big.Int {
	qlen := n.BitLen()
	b := new(big.Int).SetBytes(m)
	blen := b.BitLen()
	if qlen < blen {
		b.Rsh(b, uint(blen-qlen))
	}
	return b
}

// 2.3.3.  Integer to Octet String
// https://tools.ietf.org/html/rfc6979#section-2.3.3
func int2octets(x *big.Int) []byte {
	l := len(n.Bytes())
	bs := x.Bytes()
	if len(bs) < l {
		bs2 := make([]byte, l)
		copy(bs2[l-len(bs):], bs)
		return bs2
	}
	if len(bs) > l {
		bs2 := make([]byte, l)
		copy(bs2, bs[len(bs)-l:])
		return bs2
	}
	return bs
}

// HMAC returns a sequence of bits of length hlen with the key and the data.
// 3.1.1.  HMAC
// https://tools.ietf.org/html/rfc6979#section-3.1.1
func HMAC(key []byte, values ...[]byte) []byte {
	h := hmac.New(sha256.New, key)
	data := []byte{}
	for _, value := range values {
		data = append(data, value...)
	}
	h.Write(data)
	return h.Sum(nil)
}

// 3.2.  Generation of k
// https://tools.ietf.org/html/rfc6979#section-3.2
func nonceRFC6979(m []byte, x *big.Int) *big.Int {
	h1 := H(m)
	V := bytes.Repeat([]byte{0x01}, len(h1))
	K := make([]byte, len(h1))
	K = HMAC(K, V, []byte{0x00}, int2octets(x), h1)
	V = HMAC(K, V)
	K = HMAC(K, V, []byte{0x01}, int2octets(x), h1)
	V = HMAC(K, V)
	for {
		T := []byte{}
		tlen := new(big.Int).SetBytes(T).BitLen()
		qlen := n.BitLen()
		if tlen < qlen {
			V = HMAC(K, V)
			T = append(T, V...)
		}
		k := bits2int(T)
		if k.Cmp(big.NewInt(0)) > 0 && k.Cmp(n) < 0 {
			return k
		}
		K = HMAC(K, V, []byte{0x00})
		V = HMAC(K, V)
	}
}

// Sign returns the signature.
// 2.4.  Signature Generation
// https://tools.ietf.org/html/rfc6979#section-2.4
func Sign(m []byte, x *big.Int) (*big.Int, *big.Int) {
	h := new(big.Int).Mod(bits2int(H(m)), n)
	k := nonceRFC6979(m, x)
	R := Mul(k, G)
	r := R.X
	// s = (h + x*r) * k^(q-2)
	s := new(big.Int).Mod(
		new(big.Int).Mul(
			new(big.Int).Add(h, new(big.Int).Mul(x, r)),
			new(big.Int).Exp(k, new(big.Int).Sub(n, big.NewInt(2)), n)),
		n)
	half := new(big.Int).Rsh(n, 1)
	if s.Cmp(half) > 0 {
		s.Sub(n, s)
	}
	return r, s
}

// Verify verifies the signature in r, s of message using the public key, P.
// https://apps.nsa.gov/iaarchive/library/index.cfm
// "Suite B Implementer’s Guide to FIPS 186-3 (ECDSA)"
func Verify(P *Point, m []byte, r, s *big.Int) bool {
	if r.Cmp(big.NewInt(1)) < 0 && r.Cmp(n) >= 0 {
		return false
	}
	if s.Cmp(big.NewInt(1)) < 0 && s.Cmp(n) >= 0 {
		return false
	}
	e := bits2int(H(m))
	w := new(big.Int).Exp(s, new(big.Int).Sub(n, big.NewInt(2)), n)
	u1 := new(big.Int).Mod(new(big.Int).Mul(e, w), n)
	u2 := new(big.Int).Mod(new(big.Int).Mul(r, w), n)
	V := Add(Mul(u1, G), Mul(u2, P))
	if V.Infinite() || r.Cmp(V.X) != 0 {
		return false
	}
	return true
}

// DER returns the DER signature.
// https://github.com/libbitcoin/libbitcoin/wiki/ECDSA-and-DER-Signatures
func DER(r, s *big.Int) []byte {
	sig := []byte{0x30}
	rbs := r.Bytes()
	if r.BitLen() == len(rbs)*8 {
		rbs = append([]byte{0x00}, rbs...)
	}
	sbs := s.Bytes()
	if s.BitLen() == len(sbs)*8 {
		sbs = append([]byte{0x00}, sbs...)
	}
	sig = append(sig, byte(len(rbs)+len(sbs)+4))
	sig = append(sig, 0x02)
	sig = append(sig, byte(len(rbs)))
	sig = append(sig, rbs...)
	sig = append(sig, 0x02)
	sig = append(sig, byte(len(sbs)))
	sig = append(sig, sbs...)
	return sig
}
