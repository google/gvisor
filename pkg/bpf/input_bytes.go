// Copyright 2018 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package bpf

import (
	"encoding/binary"
)

// Input represents a source of input data for a BPF program. (BPF
// documentation sometimes refers to the input data as the "packet" due to its
// origins as a packet processing DSL.)
// Unaligned loads are supported.
type Input []byte

// These type definitions must have different GC shapes to ensure that
// the Go compiler generates distinct code paths for them.
// These do not have anything to do with the bit sizes of the loads
// later on; all that matters is that these types have distinct sizes
// from one another.
type (
	// BigEndian uses big-endian byte ordering.
	BigEndian uint8

	// LittleEndian uses little-endian byte ordering.
	LittleEndian uint16

	// NativeEndian uses native byte ordering.
	NativeEndian uint32
)

// Endianness represents a byte order.
type Endianness interface {
	BigEndian | LittleEndian | NativeEndian
}

// load32 loads a 32-bit value.
//
//go:nosplit
func load32[endian Endianness](in Input, off uint32) (uint32, bool) {
	if uint64(off)+4 > uint64(len(in)) {
		return 0, false
	}
	// Casting to any is needed here to avoid a compilation error:
	// https://go.googlesource.com/proposal/+/refs/heads/master/design/43651-type-parameters.md#why-not-permit-type-assertions-on-values-whose-type-is-a-type-parameter
	var e endian
	switch any(e).(type) {
	case BigEndian:
		return binary.BigEndian.Uint32(in[int(off):]), true
	case LittleEndian:
		return binary.LittleEndian.Uint32(in[int(off):]), true
	case NativeEndian:
		return binary.NativeEndian.Uint32(in[int(off):]), true
	default:
		panic("unreachable")
	}
}

// load16 loads a 16-bit value.
//
//go:nosplit
func load16[endian Endianness](in Input, off uint32) (uint16, bool) {
	if uint64(off)+2 > uint64(len(in)) {
		return 0, false
	}
	// Casting to any is needed here to avoid a compilation error:
	// https://go.googlesource.com/proposal/+/refs/heads/master/design/43651-type-parameters.md#why-not-permit-type-assertions-on-values-whose-type-is-a-type-parameter
	var e endian
	switch any(e).(type) {
	case BigEndian:
		return binary.BigEndian.Uint16(in[int(off):]), true
	case LittleEndian:
		return binary.LittleEndian.Uint16(in[int(off):]), true
	case NativeEndian:
		return binary.NativeEndian.Uint16(in[int(off):]), true
	default:
		panic("unreachable")
	}
}

// load8 loads a single byte.
//
//go:nosplit
func load8(in Input, off uint32) (uint8, bool) {
	if uint64(off)+1 > uint64(len(in)) {
		return 0, false
	}
	return in[int(off)], true
}
