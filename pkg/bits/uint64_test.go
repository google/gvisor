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

package bits

import (
	"reflect"
	"testing"
)

func TestTrailingZeros64(t *testing.T) {
	for i := 0; i <= 64; i++ {
		n := uint64(1) << uint(i)
		if got, want := TrailingZeros64(n), i; got != want {
			t.Errorf("TrailingZeros64(%#x): got %d, wanted %d", n, got, want)
		}
	}

	for i := 0; i < 64; i++ {
		n := ^uint64(0) << uint(i)
		if got, want := TrailingZeros64(n), i; got != want {
			t.Errorf("TrailingZeros64(%#x): got %d, wanted %d", n, got, want)
		}
	}

	for i := 0; i < 64; i++ {
		n := ^uint64(0) >> uint(i)
		if got, want := TrailingZeros64(n), 0; got != want {
			t.Errorf("TrailingZeros64(%#x): got %d, wanted %d", n, got, want)
		}
	}
}

func TestMostSignificantOne64(t *testing.T) {
	for i := 0; i <= 64; i++ {
		n := uint64(1) << uint(i)
		if got, want := MostSignificantOne64(n), i; got != want {
			t.Errorf("MostSignificantOne64(%#x): got %d, wanted %d", n, got, want)
		}
	}

	for i := 0; i < 64; i++ {
		n := ^uint64(0) >> uint(i)
		if got, want := MostSignificantOne64(n), 63-i; got != want {
			t.Errorf("MostSignificantOne64(%#x): got %d, wanted %d", n, got, want)
		}
	}

	for i := 0; i < 64; i++ {
		n := ^uint64(0) << uint(i)
		if got, want := MostSignificantOne64(n), 63; got != want {
			t.Errorf("MostSignificantOne64(%#x): got %d, wanted %d", n, got, want)
		}
	}
}

func TestForEachSetBit64(t *testing.T) {
	for _, want := range [][]int{
		{},
		{0},
		{1},
		{63},
		{0, 1},
		{1, 3, 5},
		{0, 63},
	} {
		n := Mask64(want...)
		// "Slice values are deeply equal when ... they are both nil or both
		// non-nil ..."
		got := make([]int, 0)
		ForEachSetBit64(n, func(i int) {
			got = append(got, i)
		})
		if !reflect.DeepEqual(got, want) {
			t.Errorf("ForEachSetBit64(%#x): iterated bits %v, wanted %v", n, got, want)
		}
	}
}

func TestIsOn(t *testing.T) {
	type spec struct {
		mask uint64
		bits uint64
		any  bool
		all  bool
	}
	for _, s := range []spec{
		{Mask64(0), Mask64(0), true, true},
		{Mask64(63), Mask64(63), true, true},
		{Mask64(0), Mask64(1), false, false},
		{Mask64(0), Mask64(0, 1), true, false},

		{Mask64(1, 63), Mask64(1), true, true},
		{Mask64(1, 63), Mask64(1, 63), true, true},
		{Mask64(1, 63), Mask64(0, 1, 63), true, false},
		{Mask64(1, 63), Mask64(0, 62), false, false},
	} {
		if ok := IsAnyOn64(s.mask, s.bits); ok != s.any {
			t.Errorf("IsAnyOn(%#x, %#x) = %v, wanted: %v", s.mask, s.bits, ok, s.any)
		}
		if ok := IsOn64(s.mask, s.bits); ok != s.all {
			t.Errorf("IsOn(%#x, %#x) = %v, wanted: %v", s.mask, s.bits, ok, s.all)
		}
	}
}
