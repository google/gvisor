// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// This file provides a generic Go implementation of uint128 divided by uint64.

// The code is derived from Go's generic math/big.divWW_g
// (src/math/big/arith.go), but is only used on ARM64.

package time

import "math/bits"

type word uint

const (
	_W  = bits.UintSize // word size in bits
	_W2 = _W / 2        // half word size in bits
	_B2 = 1 << _W2      // half digit base
	_M2 = _B2 - 1       // half digit mask
)

// nlz returns the number of leading zeros in x.
// Wraps bits.LeadingZeros call for convenience.
func nlz(x word) uint {
	return uint(bits.LeadingZeros(uint(x)))
}

// q = (u1<<_W + u0 - r)/y
// Adapted from Warren, Hacker's Delight, p. 152.
func divWW(u1, u0, v word) (q, r word) {
	if u1 >= v {
		return 1<<_W - 1, 1<<_W - 1
	}

	s := nlz(v)
	v <<= s

	vn1 := v >> _W2
	vn0 := v & _M2
	un32 := u1<<s | u0>>(_W-s)
	un10 := u0 << s
	un1 := un10 >> _W2
	un0 := un10 & _M2
	q1 := un32 / vn1
	rhat := un32 - q1*vn1

	for q1 >= _B2 || q1*vn0 > _B2*rhat+un1 {
		q1--
		rhat += vn1

		if rhat >= _B2 {
			break
		}
	}

	un21 := un32*_B2 + un1 - q1*v
	q0 := un21 / vn1
	rhat = un21 - q0*vn1

	for q0 >= _B2 || q0*vn0 > _B2*rhat+un0 {
		q0--
		rhat += vn1
		if rhat >= _B2 {
			break
		}
	}

	return q1*_B2 + q0, (un21*_B2 + un0 - q0*v) >> s
}
