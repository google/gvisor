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

// +checkalignedignore
package atomicbitops

import (
	"fmt"
	"math"
	"runtime"
	"testing"

	"gvisor.dev/gvisor/pkg/sync"
)

const iterations = 100

func detectRaces32(val, target uint32, fn func(*Uint32, uint32)) bool {
	runtime.GOMAXPROCS(100)
	for n := 0; n < iterations; n++ {
		x := FromUint32(val)
		var wg sync.WaitGroup
		for i := uint32(0); i < 32; i++ {
			wg.Add(1)
			go func(a *Uint32, i uint32) {
				defer wg.Done()
				fn(a, uint32(1<<i))
			}(&x, i)
		}
		wg.Wait()
		if x != FromUint32(target) {
			return true
		}
	}
	return false
}

func detectRaces64(val, target uint64, fn func(*Uint64, uint64)) bool {
	runtime.GOMAXPROCS(100)
	for n := 0; n < iterations; n++ {
		x := FromUint64(val)
		var wg sync.WaitGroup
		for i := uint64(0); i < 64; i++ {
			wg.Add(1)
			go func(a *Uint64, i uint64) {
				defer wg.Done()
				fn(a, uint64(1<<i))
			}(&x, i)
		}
		wg.Wait()
		if x != FromUint64(target) {
			return true
		}
	}
	return false
}

func TestOrUint32(t *testing.T) {
	if detectRaces32(0x0, 0xffffffff, OrUint32) {
		t.Error("Data race detected!")
	}
}

func TestAndUint32(t *testing.T) {
	if detectRaces32(0xf0f0f0f0, 0x00000000, AndUint32) {
		t.Error("Data race detected!")
	}
}

func TestXorUint32(t *testing.T) {
	if detectRaces32(0xf0f0f0f0, 0x0f0f0f0f, XorUint32) {
		t.Error("Data race detected!")
	}
}

func TestOrUint64(t *testing.T) {
	if detectRaces64(0x0, 0xffffffffffffffff, OrUint64) {
		t.Error("Data race detected!")
	}
}

func TestAndUint64(t *testing.T) {
	if detectRaces64(0xf0f0f0f0f0f0f0f0, 0x0, AndUint64) {
		t.Error("Data race detected!")
	}
}

func TestXorUint64(t *testing.T) {
	if detectRaces64(0xf0f0f0f0f0f0f0f0, 0x0f0f0f0f0f0f0f0f, XorUint64) {
		t.Error("Data race detected!")
	}
}

func TestCompareAndSwapUint32(t *testing.T) {
	tests := []struct {
		name string
		prev uint32
		old  uint32
		new  uint32
		next uint32
	}{
		{
			name: "Successful compare-and-swap with prev == new",
			prev: 10,
			old:  10,
			new:  10,
			next: 10,
		},
		{
			name: "Successful compare-and-swap with prev != new",
			prev: 20,
			old:  20,
			new:  22,
			next: 22,
		},
		{
			name: "Failed compare-and-swap with prev == new",
			prev: 31,
			old:  30,
			new:  31,
			next: 31,
		},
		{
			name: "Failed compare-and-swap with prev != new",
			prev: 41,
			old:  40,
			new:  42,
			next: 41,
		},
	}
	for _, test := range tests {
		val := FromUint32(test.prev)
		prev := CompareAndSwapUint32(&val, test.old, test.new)
		if got, want := prev, test.prev; got != want {
			t.Errorf("%s: incorrect returned previous value: got %d, expected %d", test.name, got, want)
		}
		if got, want := val.Load(), test.next; got != want {
			t.Errorf("%s: incorrect value stored in val: got %d, expected %d", test.name, got, want)
		}
	}
}

func TestCompareAndSwapUint64(t *testing.T) {
	tests := []struct {
		name string
		prev uint64
		old  uint64
		new  uint64
		next uint64
	}{
		{
			name: "Successful compare-and-swap with prev == new",
			prev: 0x100000000,
			old:  0x100000000,
			new:  0x100000000,
			next: 0x100000000,
		},
		{
			name: "Successful compare-and-swap with prev != new",
			prev: 0x200000000,
			old:  0x200000000,
			new:  0x200000002,
			next: 0x200000002,
		},
		{
			name: "Failed compare-and-swap with prev == new",
			prev: 0x300000001,
			old:  0x300000000,
			new:  0x300000001,
			next: 0x300000001,
		},
		{
			name: "Failed compare-and-swap with prev != new",
			prev: 0x400000001,
			old:  0x400000000,
			new:  0x400000002,
			next: 0x400000001,
		},
	}
	for _, test := range tests {
		val := FromUint64(test.prev)
		prev := CompareAndSwapUint64(&val, test.old, test.new)
		if got, want := prev, test.prev; got != want {
			t.Errorf("%s: incorrect returned previous value: got %d, expected %d", test.name, got, want)
		}
		if got, want := val.Load(), test.next; got != want {
			t.Errorf("%s: incorrect value stored in val: got %d, expected %d", test.name, got, want)
		}
	}
}

var interestingFloats = []float64{
	0.0,
	1.0,
	0.1,
	2.1,
	-1.0,
	-0.1,
	-2.1,
	math.MaxFloat64,
	-math.MaxFloat64,
	math.SmallestNonzeroFloat64,
	-math.SmallestNonzeroFloat64,
	math.Inf(1),
	math.Inf(-1),
	math.NaN(),
}

// equalOrBothNaN returns true if a == b or if a and b are both NaN.
func equalOrBothNaN(a, b float64) bool {
	return a == b || (math.IsNaN(a) && math.IsNaN(b))
}

// getInterestingFloatPermutations returns a list of `num`-sized permutations
// of the floating-point values in `interestingFloats`.
func getInterestingFloatPermutations(num int) [][]float64 {
	permutations := make([][]float64, 0, len(interestingFloats))
	for _, f := range interestingFloats {
		permutations = append(permutations, []float64{f})
	}
	for i := 1; i < num; i++ {
		oldPermutations := permutations
		permutations = make([][]float64, 0, len(permutations)*len(interestingFloats))
		for _, oldPermutation := range oldPermutations {
			for _, f := range interestingFloats {
				alreadyInPermutation := false
				for _, f2 := range oldPermutation {
					if equalOrBothNaN(f, f2) {
						alreadyInPermutation = true
						break
					}
				}
				if alreadyInPermutation {
					continue
				}
				permutations = append(permutations, append(oldPermutation, f))
			}
		}

	}
	return permutations
}

func TestCompareAndSwapFloat64(t *testing.T) {
	for _, floats := range getInterestingFloatPermutations(3) {
		a, b, c := floats[0], floats[1], floats[2]
		t.Run(fmt.Sprintf("a=%v b=%v c=%v", a, b, c), func(t *testing.T) {
			tests := []struct {
				name string
				prev float64
				old  float64
				new  float64
				next float64
			}{
				{
					name: "Successful compare-and-swap with prev == new",
					prev: a,
					old:  a,
					new:  a,
					next: a,
				},
				{
					name: "Successful compare-and-swap with prev != new",
					prev: a,
					old:  a,
					new:  b,
					next: b,
				},
				{
					name: "Failed compare-and-swap with prev == new",
					prev: a,
					old:  b,
					new:  a,
					next: a,
				},
				{
					name: "Failed compare-and-swap with prev != new",
					prev: a,
					old:  b,
					new:  c,
					next: a,
				},
			}
			for _, test := range tests {
				t.Run(test.name, func(t *testing.T) {
					val := FromFloat64(test.prev)
					success := val.CompareAndSwap(test.old, test.new)
					wantSuccess := equalOrBothNaN(test.prev, test.old) && equalOrBothNaN(test.new, test.next)
					if success != wantSuccess {
						t.Errorf("incorrect success value: got %v, expected %v", success, wantSuccess)
					}
					if got, want := val.Load(), test.next; !equalOrBothNaN(got, want) {
						t.Errorf("incorrect value stored in val: got %v, expected %v", got, want)
					}
				})
			}
		})
	}
}

func TestAddFloat64(t *testing.T) {
	runtime.GOMAXPROCS(100)
	for _, floats := range getInterestingFloatPermutations(3) {
		a, b, c := floats[0], floats[1], floats[2]
		// This test computes the outcome of adding `b` and `c` to `a`.
		// Because floating point numbers lose precision with each operation,
		// it is not always the case that a + b + c = a + c + b.
		// Therefore, it computes both a + b + c and a + c + b, and verifies that
		// adding Float64s in that order works exactly, while Float64s to which
		// `b` and `c` are added in separate goroutines may end up at either
		// `a + b + c` or `a + c + b`.
		testName := fmt.Sprintf("a=%v b=%v c=%v", a, b, c)
		for i := 0; i < iterations; i++ {
			fCanonical := a
			fCanonicalReverse := a
			fLinear := FromFloat64(a)
			fLinearReverse := FromFloat64(a)
			fParallel1 := FromFloat64(a)
			fParallel2 := FromFloat64(a)
			var wg sync.WaitGroup
			spawn := func(f func()) {
				wg.Add(1)
				go func() {
					defer wg.Done()
					f()
				}()
			}
			spawn(func() {
				fCanonical += b
				fCanonical += c
			})
			spawn(func() {
				fCanonicalReverse += c
				fCanonicalReverse += b
			})
			spawn(func() {
				fLinear.Add(b)
				fLinear.Add(c)
			})
			spawn(func() {
				fLinearReverse.Add(c)
				fLinearReverse.Add(b)
			})
			spawn(func() {
				fParallel1.Add(b)
			})
			spawn(func() {
				fParallel2.Add(c)
			})
			spawn(func() {
				fParallel1.Add(c)
			})
			spawn(func() {
				fParallel2.Add(b)
			})
			wg.Wait()
			for _, f := range []struct {
				name string
				val  float64
				want []float64
			}{
				{"linear", fLinear.Load(), []float64{fCanonical}},
				{"linear reverse", fLinearReverse.Load(), []float64{fCanonicalReverse}},
				{"parallel 1", fParallel1.Load(), []float64{fCanonical, fCanonicalReverse}},
				{"parallel 2", fParallel2.Load(), []float64{fCanonical, fCanonicalReverse}},
			} {
				found := false
				for _, want := range f.want {
					if equalOrBothNaN(f.val, want) {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("%s: %s was not equal to expected result: %v not in %v", testName, f.name, f.val, f.want)
				}
			}
		}
	}
}
