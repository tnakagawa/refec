package main

import (
	"encoding/hex"
	"fmt"
	"math/big"
)

func main() {
	fmt.Println("Sample Elliptic Curve")
}

// p is a prime number of secp256k1.
// http://www.secg.org/sec2-v2.pdf
var p, _ = new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16)

// Point is a coordinate of elliptic curve.
type Point struct {
	X *big.Int
	Y *big.Int
}

// Infinite returns whether it is at infinity or not.
func (point *Point) Infinite() bool {
	if point.X == nil || point.Y == nil {
		return true
	}
	return false
}

// Clone returns a copy of Point.
func (point *Point) Clone() *Point {
	clone := &Point{}
	if point.Infinite() {
		return nil
	}
	clone.X = new(big.Int).SetBytes(point.X.Bytes())
	clone.Y = new(big.Int).SetBytes(point.Y.Bytes())
	return clone
}

// Compressed returns the compressed Point.
func (point *Point) Compressed() []byte {
	if point.Infinite() {
		return nil
	}
	size := len(p.Bytes())
	bs := new(big.Int).Mod(point.X, p).Bytes()
	for len(bs) != size {
		bs = append([]byte{0x00}, bs...)
	}
	if point.Y.Bit(0) == 0 {
		bs = append([]byte{0x02}, bs...)
	} else {
		bs = append([]byte{0x03}, bs...)
	}
	return bs
}

// Decode returns a Point from the bytes.
func Decode(bs []byte) (*Point, error) {
	size := len(p.Bytes())
	if len(bs) == 1+2*size {
		if bs[0] != 0x04 {
			return nil, fmt.Errorf("invalid format : %x", bs)
		}
		point := &Point{}
		point.X = new(big.Int).SetBytes(bs[1 : size+1])
		point.Y = new(big.Int).SetBytes(bs[size+1:])
		return point, nil
	}
	if len(bs) != 1+size {
		return nil, fmt.Errorf("invalid length : %x", bs)
	}
	if bs[0] != 0x02 && bs[0] != 0x03 {
		return nil, fmt.Errorf("invalid format : %x", bs)
	}
	point := &Point{}
	point.X = new(big.Int).SetBytes(bs[1:])
	// (x^3 + 7)^((p + 1) / 4)
	point.Y = new(big.Int).Exp(
		new(big.Int).Add(new(big.Int).Exp(point.X, big.NewInt(3), p), big.NewInt(7)),
		new(big.Int).Div(new(big.Int).Add(p, big.NewInt(1)), big.NewInt(4)),
		p)
	if (bs[0] != 0x02 && point.Y.Bit(0) == 0) || (bs[0] != 0x03 && point.Y.Bit(0) == 1) {
		point.Y.Sub(p, point.Y)
	}
	return point, nil
}

// DecodeString returns a Point from the hexstring.
func DecodeString(hexstring string) (*Point, error) {
	bs, err := hex.DecodeString(hexstring)
	if err != nil {
		return nil, err
	}
	return Decode(bs)
}

// G is the base point of secp256k1.
var G, _ = DecodeString("0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798")

// n is the order of G.
var n, _ = new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)

// Add returns the addition of Points.
func Add(P, Q *Point) *Point {
	if P.Infinite() {
		return Q.Clone()
	}
	if Q.Infinite() {
		return P.Clone()
	}
	if P.X.Cmp(Q.X) == 0 && Q.Y.Cmp(Q.Y) != 0 {
		return &Point{}
	}
	var s *big.Int
	if P.X.Cmp(Q.X) == 0 && P.Y.Cmp(Q.Y) == 0 {
		// (3xP^2) * (2 * yP)^(p - 2) mod p
		s = new(big.Int).Mod(
			new(big.Int).Mul(
				new(big.Int).Mul(new(big.Int).Mul(big.NewInt(3), P.X), P.X),
				new(big.Int).Exp(
					new(big.Int).Mul(big.NewInt(2), P.Y),
					new(big.Int).Sub(p, big.NewInt(2)),
					p)),
			p)
	} else {
		// (yP - yQ) * (xP - xQ)^(p - 2) mod p
		s = new(big.Int).Mod(
			new(big.Int).Mul(
				new(big.Int).Sub(P.Y, Q.Y),
				new(big.Int).Exp(
					new(big.Int).Sub(P.X, Q.X),
					new(big.Int).Sub(p, big.NewInt(2)),
					p)),
			p)
	}
	R := &Point{}
	// xR = s*s - (xP + xQ) mod p
	R.X = new(big.Int).Mod(new(big.Int).Sub(new(big.Int).Mul(s, s), new(big.Int).Add(P.X, Q.X)), p)
	// -yR = s*(xP - xR) - yP mod p
	R.Y = new(big.Int).Mod(new(big.Int).Sub(new(big.Int).Mul(s, new(big.Int).Sub(P.X, R.X)), P.Y), p)
	return R
}

// Mul is the multiple of Point.
func Mul(x *big.Int, P *Point) *Point {
	R := &Point{}
	for i := 0; i < x.BitLen(); i++ {
		if x.Bit(i) == 1 {
			R = Add(R, P)
		}
		P = Add(P, P)
	}
	return R
}
