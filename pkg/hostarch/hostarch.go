// Copyright 2021 The gVisor Authors.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd.

// Package hostarch contains machine architecture parameters.
package hostarch

import (
	"encoding/binary"
	"fmt"
)

// EndianString returns "little" if the invoking process is little-endian and
// "big" if the invoking process is big-endian.
func EndianString() string {
	switch val := binary.NativeEndian.Uint32([]byte{0x01, 0x02, 0x03, 0x04}); val {
	case 0x01020304:
		return "big"
	case 0x04030201:
		return "little"
	default:
		panic(fmt.Sprintf("unknown endianness: [01 02 03 04] => %#x", val))
	}
}
