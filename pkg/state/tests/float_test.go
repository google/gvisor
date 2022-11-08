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

var safeFloat32s = []float32{
	float32(0.0),
	float32(1.0),
	float32(-1.0),
	float32(math.Inf(1)),
	float32(math.Inf(-1)),
}

var allFloat32s = append(safeFloat32s, float32(math.NaN()))

var safeFloat64s = []float64{
	float64(0.0),
	float64(1.0),
	float64(-1.0),
	math.Inf(1),
	math.Inf(-1),
}

var allFloat64s = append(safeFloat64s, math.NaN())

func TestFloat(t *testing.T) {
	runTestCases(t, false, "plain", flatten(
		allFloat32s,
		allFloat64s,
	))
	// See checkEqual for why NaNs are missing.
	runTestCases(t, false, "pointers", pointersTo(flatten(
		safeFloat32s,
		safeFloat64s,
	)))
	runTestCases(t, false, "interfaces", interfacesTo(flatten(
		safeFloat32s,
		safeFloat64s,
	)))
	runTestCases(t, false, "interfacesToPointers", interfacesTo(pointersTo(flatten(
		safeFloat32s,
		safeFloat64s,
	))))
}

const onlyDouble float64 = 1.0000000000000002

func TestFloatTruncation(t *testing.T) {
	runTestCases(t, true, "pass", []any{
		truncatingFloat32{save: onlyDouble},
	})
	runTestCases(t, false, "fail", []any{
		truncatingFloat32{save: 1.0},
	})
}

var safeComplex64s = combine(safeFloat32s, safeFloat32s, func(i, j any) any {
	return complex(i.(float32), j.(float32))
})

var allComplex64s = combine(allFloat32s, allFloat32s, func(i, j any) any {
	return complex(i.(float32), j.(float32))
})

var safeComplex128s = combine(safeFloat64s, safeFloat64s, func(i, j any) any {
	return complex(i.(float64), j.(float64))
})

var allComplex128s = combine(allFloat64s, allFloat64s, func(i, j any) any {
	return complex(i.(float64), j.(float64))
})

func TestComplex(t *testing.T) {
	runTestCases(t, false, "plain", flatten(
		allComplex64s,
		allComplex128s,
	))
	// See TestFloat; same issue.
	runTestCases(t, false, "pointers", pointersTo(flatten(
		safeComplex64s,
		safeComplex128s,
	)))
	runTestCases(t, false, "interfacse", interfacesTo(flatten(
		safeComplex64s,
		safeComplex128s,
	)))
	runTestCases(t, false, "interfacesTo", interfacesTo(pointersTo(flatten(
		safeComplex64s,
		safeComplex128s,
	))))
}

func TestComplexTruncation(t *testing.T) {
	runTestCases(t, true, "pass", []any{
		truncatingComplex64{save: complex(onlyDouble, onlyDouble)},
		truncatingComplex64{save: complex(1.0, onlyDouble)},
		truncatingComplex64{save: complex(onlyDouble, 1.0)},
	})
	runTestCases(t, false, "fail", []any{
		truncatingComplex64{save: complex(1.0, 1.0)},
	})
}
