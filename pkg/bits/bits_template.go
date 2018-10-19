// Copyright 2018 Google LLC
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

// Non-atomic bit operations on a template type T.

// T is a required type parameter that must be an integral type.
type T uint64

// IsOn returns true if *all* bits set in 'bits' are set in 'mask'.
func IsOn(mask, bits T) bool {
	return mask&bits == bits
}

// IsAnyOn returns true if *any* bit set in 'bits' is set in 'mask'.
func IsAnyOn(mask, bits T) bool {
	return mask&bits != 0
}

// Mask returns a T with all of the given bits set.
func Mask(is ...int) T {
	ret := T(0)
	for _, i := range is {
		ret |= MaskOf(i)
	}
	return ret
}

// MaskOf is like Mask, but sets only a single bit (more efficiently).
func MaskOf(i int) T {
	return T(1) << T(i)
}
