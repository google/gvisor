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

package tests

import (
	"math"
	"testing"
)

var (
	allBasicInts  = []int{-1, 0, 1}
	allInt8s      = []int8{math.MinInt8, -1, 0, 1, math.MaxInt8}
	allInt16s     = []int16{math.MinInt16, -1, 0, 1, math.MaxInt16}
	allInt32s     = []int32{math.MinInt32, -1, 0, 1, math.MaxInt32}
	allInt64s     = []int64{math.MinInt64, -1, 0, 1, math.MaxInt64}
	allBasicUints = []uint{0, 1}
	allUintptrs   = []uintptr{0, 1, ^uintptr(0)}
	allUint8s     = []uint8{0, 1, math.MaxUint8}
	allUint16s    = []uint16{0, 1, math.MaxUint16}
	allUint32s    = []uint32{0, 1, math.MaxUint32}
	allUint64s    = []uint64{0, 1, math.MaxUint64}
)

var allInts = flatten(
	allBasicInts,
	allInt8s,
	allInt16s,
	allInt32s,
	allInt64s,
)

var allUints = flatten(
	allBasicUints,
	allUintptrs,
	allUint8s,
	allUint16s,
	allUint32s,
	allUint64s,
)

func TestInt(t *testing.T) {
	runTestCases(t, false, "plain", allInts)
	runTestCases(t, false, "pointers", pointersTo(allInts))
	runTestCases(t, false, "interfaces", interfacesTo(allInts))
	runTestCases(t, false, "interfacesTo", interfacesTo(pointersTo(allInts)))
}

func TestIntTruncation(t *testing.T) {
	runTestCases(t, true, "pass", []any{
		truncatingInt8{save: math.MinInt8 - 1},
		truncatingInt16{save: math.MinInt16 - 1},
		truncatingInt32{save: math.MinInt32 - 1},
		truncatingInt8{save: math.MaxInt8 + 1},
		truncatingInt16{save: math.MaxInt16 + 1},
		truncatingInt32{save: math.MaxInt32 + 1},
	})
	runTestCases(t, false, "fail", []any{
		truncatingInt8{save: 1},
		truncatingInt16{save: 1},
		truncatingInt32{save: 1},
	})
}

func TestUint(t *testing.T) {
	runTestCases(t, false, "plain", allUints)
	runTestCases(t, false, "pointers", pointersTo(allUints))
	runTestCases(t, false, "interfaces", interfacesTo(allUints))
	runTestCases(t, false, "interfacesTo", interfacesTo(pointersTo(allUints)))
}

func TestUintTruncation(t *testing.T) {
	runTestCases(t, true, "pass", []any{
		truncatingUint8{save: math.MaxUint8 + 1},
		truncatingUint16{save: math.MaxUint16 + 1},
		truncatingUint32{save: math.MaxUint32 + 1},
	})
	runTestCases(t, false, "fail", []any{
		truncatingUint8{save: 1},
		truncatingUint16{save: 1},
		truncatingUint32{save: 1},
	})
}
