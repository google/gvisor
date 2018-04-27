// Copyright 2018 Google Inc.
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

// +build !amd64

package bits

// TrailingZeros64 returns the number of bits before the least significant 1
// bit in x; in other words, it returns the index of the least significant 1
// bit in x. If x is 0, TrailingZeros64 returns 64.
func TrailingZeros64(x uint64) int {
	if x == 0 {
		return 64
	}
	i := 0
	for ; x&1 == 0; i++ {
		x >>= 1
	}
	return i
}

// MostSignificantOne64 returns the index of the most significant 1 bit in
// x. If x is 0, MostSignificantOne64 returns 64.
func MostSignificantOne64(x uint64) int {
	if x == 0 {
		return 64
	}
	i := 63
	for ; x&(1<<63) == 0; i-- {
		x <<= 1
	}
	return i
}

// ForEachSetBit64 calls f once for each set bit in x, with argument i equal to
// the set bit's index.
func ForEachSetBit64(x uint64, f func(i int)) {
	for i := 0; x != 0; i++ {
		if x&1 != 0 {
			f(i)
		}
		x >>= 1
	}
}
