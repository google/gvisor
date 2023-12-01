// Copyright 2023 The gVisor Authors.
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

// Package rand implements a cryptographically secure pseudorandom number
// generator.
package rand

import (
	"encoding/binary"
	"fmt"
	"io"
)

// RNG exposes convenience functions based on a cryptographically secure
// io.Reader.
type RNG struct {
	Reader io.Reader
}

// RNGFrom returns a new RNG. r must be a cryptographically secure io.Reader.
func RNGFrom(r io.Reader) RNG {
	return RNG{Reader: r}
}

// Uint16 is analogous to the standard library's math/rand.Uint16.
func (rg *RNG) Uint16() uint16 {
	var data [2]byte
	if _, err := rg.Reader.Read(data[:]); err != nil {
		panic(fmt.Sprintf("Read() failed: %v", err))
	}
	return binary.NativeEndian.Uint16(data[:])
}

// Uint32 is analogous to the standard library's math/rand.Uint32.
func (rg *RNG) Uint32() uint32 {
	var data [4]byte
	if _, err := rg.Reader.Read(data[:]); err != nil {
		panic(fmt.Sprintf("Read() failed: %v", err))
	}
	return binary.NativeEndian.Uint32(data[:])
}

// Int63n is analogous to the standard library's math/rand.Int63n.
func (rg *RNG) Int63n(n int64) int64 {
	// Based on Go's rand package implementation, but using
	// cryptographically secure random numbers.
	if n <= 0 {
		panic(fmt.Sprintf("n must be positive, but got %d", n))
	}

	// This can be done quickly when n is a power of 2.
	if n&(n-1) == 0 {
		return int64(rg.Uint64()) & (n - 1)
	}

	// The naive approach would be to return rg.Int63()%n, but we need the
	// random number to be fair. It shouldn't be biased towards certain
	// results, but simple modular math can be very biased. For example, if
	// n is 40% of the maximum int64, then the output values of rg.Int63
	// map to return values as follows:
	//
	//  - The first 40% of values map to themselves.
	//  - The second 40% map to themselves - maximum int64.
	//  - The remaining 20% map to the themselves - 2 * (maximum int64),
	//    i.e. the first half of possible output values.
	//
	// And thus 60% of results map the the first half of possible output
	// values, and 40% map the second half. Oops!
	//
	// We use the same trick as Go to deal with this: shave off the last
	// segment (the 20% in our example) to make the RNG more fair.
	//
	// In the worst case, n is just over half of maximum int64, meaning
	// that the upper half of rg.Int63 return values are bad. So each call
	// to rg.Int63 has, at worst, a 50% chance of needing a retry.
	maximum := int64((1 << 63) - 1 - (1<<63)%uint64(n))
	ret := rg.Int63()
	for ret > maximum {
		ret = rg.Int63()
	}
	return ret % n
}

// Int63 is analogous to the standard library's math/rand.Int63.
func (rg *RNG) Int63() int64 {
	return ((1 << 63) - 1) & int64(rg.Uint64())
}

// Uint64 is analogous to the standard library's math/rand.Uint64.
func (rg *RNG) Uint64() uint64 {
	var data [8]byte
	if _, err := rg.Reader.Read(data[:]); err != nil {
		panic(fmt.Sprintf("Read() failed: %v", err))
	}
	return binary.NativeEndian.Uint64(data[:])
}

// Uint32 is analogous to the standard library's math/rand.Uint32.
func Uint32() uint32 {
	rng := RNG{Reader: Reader}
	return rng.Uint32()
}

// Int63n is analogous to the standard library's math/rand.Int63n.
func Int63n(n int64) int64 {
	rng := RNG{Reader: Reader}
	return rng.Int63n(n)
}

// Int63 is analogous to the standard library's math/rand.Int63.
func Int63() int64 {
	rng := RNG{Reader: Reader}
	return rng.Int63()
}

// Uint64 is analogous to the standard library's math/rand.Uint64.
func Uint64() uint64 {
	rng := RNG{Reader: Reader}
	return rng.Uint64()
}
