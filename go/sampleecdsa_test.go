package main

import (
	"crypto/rand"
	"testing"

	"github.com/btcsuite/btcd/btcec"
)

func TestECDSA(t *testing.T) {
	loop := 100
	for i := 0; i < loop; i++ {
		m := make([]byte, 32)
		rand.Read(m)
		hash := H(m)
		key, err := btcec.NewPrivateKey(btcec.S256())
		if err != nil {
			t.Errorf("%v", err)
			return
		}
		// btcec sign
		sig, err := key.Sign(hash)
		if err != nil {
			t.Errorf("%v", err)
			return
		}
		// sign
		r, s := Sign(m, key.D)
		// btcec verify
		sig, err = btcec.ParseDERSignature(DER(r, s), btcec.S256())
		if err != nil {
			t.Errorf("%v", err)
			return
		}
		result := sig.Verify(hash, key.PubKey())
		if !result {
			t.Errorf("verify error %v", result)
			return
		}
		// verify
		P := Mul(key.D, G)
		result = Verify(P, m, sig.R, sig.S)
		if !result {
			t.Errorf("verify error %v", result)
			return
		}
	}
}
