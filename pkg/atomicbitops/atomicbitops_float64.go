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

package atomicbitops

import (
	"math"

	"gvisor.dev/gvisor/pkg/sync"
)

// Float64 is an atomic 64-bit floating-point number.
//
// +stateify savable
type Float64 struct {
	_ sync.NoCopy
	// bits stores the bit of a 64-bit floating point number.
	// It is not (and should not be interpreted as) a real uint64.
	bits Uint64
}

// FromFloat64 returns a Float64 initialized to value v.
//
//go:nosplit
func FromFloat64(v float64) Float64 {
	return Float64{bits: FromUint64(math.Float64bits(v))}
}

// Load loads the floating-point value.
//
//go:nosplit
func (f *Float64) Load() float64 {
	return math.Float64frombits(f.bits.Load())
}

// RacyLoad is analogous to reading an atomic value without using
// synchronization.
//
// It may be helpful to document why a racy operation is permitted.
//
//go:nosplit
func (f *Float64) RacyLoad() float64 {
	return math.Float64frombits(f.bits.RacyLoad())
}

// Store stores the given floating-point value in the Float64.
//
//go:nosplit
func (f *Float64) Store(v float64) {
	f.bits.Store(math.Float64bits(v))
}

// RacyStore is analogous to setting an atomic value without using
// synchronization.
//
// It may be helpful to document why a racy operation is permitted.
//
//go:nosplit
func (f *Float64) RacyStore(v float64) {
	f.bits.RacyStore(math.Float64bits(v))
}

// Swap stores the given value and returns the previously-stored one.
//
//go:nosplit
func (f *Float64) Swap(v float64) float64 {
	return math.Float64frombits(f.bits.Swap(math.Float64bits(v)))
}

// CompareAndSwap does a compare-and-swap operation on the float64 value.
// Note that unlike typical IEEE 754 semantics, this function will treat NaN
// as equal to itself if all of its bits exactly match.
//
//go:nosplit
func (f *Float64) CompareAndSwap(oldVal, newVal float64) bool {
	return f.bits.CompareAndSwap(math.Float64bits(oldVal), math.Float64bits(newVal))
}

// Add increments the float by the given value.
// Note that unlike an atomic integer, this requires spin-looping until we win
// the compare-and-swap race, so this may take an indeterminate amount of time.
//
//go:nosplit
func (f *Float64) Add(v float64) {
	// We do a racy load here because we optimistically think it may pass the
	// compare-and-swap operation. If it doesn't, we'll load it safely, so this
	// is OK and not a race for the overall intent of the user to add a number.
	sync.RaceDisable()
	oldVal := f.RacyLoad()
	for !f.CompareAndSwap(oldVal, oldVal+v) {
		oldVal = f.Load()
	}
	sync.RaceEnable()
}
