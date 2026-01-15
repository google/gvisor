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

package bits

import "golang.org/x/exp/constraints"

// Non-atomic bit operations on integral types.

// IsOn returns true if *all* bits set in 'bits' are set in 'mask'.
func IsOn[T constraints.Integer](mask, bits T) bool {
	return mask&bits == bits
}

// IsAnyOn returns true if *any* bit set in 'bits' is set in 'mask'.
func IsAnyOn[T constraints.Integer](mask, bits T) bool {
	return mask&bits != 0
}

// Mask returns a T with all of the given bits set.
func Mask[T constraints.Integer](is ...int) T {
	ret := T(0)
	for _, i := range is {
		ret |= MaskOf[T](i)
	}
	return ret
}

// MaskOf is like Mask, but sets only a single bit (more efficiently).
func MaskOf[T constraints.Integer](i int) T {
	return T(1) << T(i)
}

// IsPowerOfTwo returns true if v is power of 2.
func IsPowerOfTwo[T constraints.Integer](v T) bool {
	if v == 0 {
		return false
	}
	return v&(v-1) == 0
}
