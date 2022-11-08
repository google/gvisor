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

// Package tests tests the state packages.
package tests

import (
	"bytes"
	"context"
	"fmt"
	"math"
	"reflect"
	"testing"

	"gvisor.dev/gvisor/pkg/state"
	"gvisor.dev/gvisor/pkg/state/pretty"
)

// discard is an implementation of wire.Writer.
type discard struct{}

// Write implements wire.Writer.Write.
func (discard) Write(p []byte) (int, error) { return len(p), nil }

// WriteByte implements wire.Writer.WriteByte.
func (discard) WriteByte(byte) error { return nil }

// checkEqual checks if two objects are equal.
//
// N.B. This only handles one level of dereferences for NaN. Otherwise we
// would need to fork the entire implementation of reflect.DeepEqual.
func checkEqual(root, loadedValue any) bool {
	if reflect.DeepEqual(root, loadedValue) {
		return true
	}

	// NaN is not equal to itself. We handle the case of raw floating point
	// primitives here, but don't handle this case nested.
	rf32, ok1 := root.(float32)
	lf32, ok2 := loadedValue.(float32)
	if ok1 && ok2 && math.IsNaN(float64(rf32)) && math.IsNaN(float64(lf32)) {
		return true
	}
	rf64, ok1 := root.(float64)
	lf64, ok2 := loadedValue.(float64)
	if ok1 && ok2 && math.IsNaN(rf64) && math.IsNaN(lf64) {
		return true
	}

	// Same real for complex numbers.
	rc64, ok1 := root.(complex64)
	lc64, ok2 := root.(complex64)
	if ok1 && ok2 {
		return checkEqual(real(rc64), real(lc64)) && checkEqual(imag(rc64), imag(lc64))
	}
	rc128, ok1 := root.(complex128)
	lc128, ok2 := root.(complex128)
	if ok1 && ok2 {
		return checkEqual(real(rc128), real(lc128)) && checkEqual(imag(rc128), imag(lc128))
	}

	return false
}

// runTestCases runs a test for each object in objects.
func runTestCases(t *testing.T, shouldFail bool, prefix string, objects []any) {
	t.Helper()
	for i, root := range objects {
		t.Run(fmt.Sprintf("%s%d", prefix, i), func(t *testing.T) {
			t.Logf("Original object:\n%#v", root)

			// Save the passed object.
			saveBuffer := &bytes.Buffer{}
			saveObjectPtr := reflect.New(reflect.TypeOf(root))
			saveObjectPtr.Elem().Set(reflect.ValueOf(root))
			saveStats, err := state.Save(context.Background(), saveBuffer, saveObjectPtr.Interface())
			if err != nil {
				if shouldFail {
					return
				}
				t.Fatalf("Save failed unexpectedly: %v", err)
			}

			// Dump the serialized proto to aid with debugging.
			var ppBuf bytes.Buffer
			t.Logf("Raw state:\n%v", saveBuffer.Bytes())
			if err := pretty.PrintText(&ppBuf, bytes.NewReader(saveBuffer.Bytes())); err != nil {
				// We don't count this as a test failure if we
				// have shouldFail set, but we will count as a
				// failure if we were not expecting to fail.
				if !shouldFail {
					t.Errorf("PrettyPrint(html=false) failed unexpected: %v", err)
				}
			}
			if err := pretty.PrintHTML(discard{}, bytes.NewReader(saveBuffer.Bytes())); err != nil {
				// See above.
				if !shouldFail {
					t.Errorf("PrettyPrint(html=true) failed unexpected: %v", err)
				}
			}
			t.Logf("Encoded state:\n%s", ppBuf.String())
			t.Logf("Save stats:\n%s", saveStats.String())

			// Load a new copy of the object.
			loadObjectPtr := reflect.New(reflect.TypeOf(root))
			loadStats, err := state.Load(context.Background(), bytes.NewReader(saveBuffer.Bytes()), loadObjectPtr.Interface())
			if err != nil {
				if shouldFail {
					return
				}
				t.Fatalf("Load failed unexpectedly: %v", err)
			}

			// Compare the values.
			loadedValue := loadObjectPtr.Elem().Interface()
			if !checkEqual(root, loadedValue) {
				if shouldFail {
					return
				}
				t.Fatalf("Objects differ:\n\toriginal: %#v\n\tloaded:   %#v\n", root, loadedValue)
			}

			// Everything went okay. Is that good?
			if shouldFail {
				t.Fatalf("This test was expected to fail, but didn't.")
			}
			t.Logf("Load stats:\n%s", loadStats.String())

			// Truncate half the bytes in the byte stream,
			// and ensure that we can't restore. Then
			// truncate only the final byte and ensure that
			// we can't restore.
			l := saveBuffer.Len()
			halfReader := bytes.NewReader(saveBuffer.Bytes()[:l/2])
			if _, err := state.Load(context.Background(), halfReader, loadObjectPtr.Interface()); err == nil {
				t.Errorf("Load with half bytes succeeded unexpectedly.")
			}
			missingByteReader := bytes.NewReader(saveBuffer.Bytes()[:l-1])
			if _, err := state.Load(context.Background(), missingByteReader, loadObjectPtr.Interface()); err == nil {
				t.Errorf("Load with missing byte succeeded unexpectedly.")
			}
		})
	}
}

// convert converts the slice to an []any.
func convert(v any) (r []any) {
	s := reflect.ValueOf(v) // Must be slice.
	for i := 0; i < s.Len(); i++ {
		r = append(r, s.Index(i).Interface())
	}
	return r
}

// flatten flattens multiple slices.
func flatten(vs ...any) (r []any) {
	for _, v := range vs {
		r = append(r, convert(v)...)
	}
	return r
}

// filter maps from one slice to another.
func filter(vs any, fn func(any) (any, bool)) (r []any) {
	s := reflect.ValueOf(vs)
	for i := 0; i < s.Len(); i++ {
		v, ok := fn(s.Index(i).Interface())
		if ok {
			r = append(r, v)
		}
	}
	return r
}

// combine combines objects in two slices as specified.
func combine(v1, v2 any, fn func(_, _ any) any) (r []any) {
	s1 := reflect.ValueOf(v1)
	s2 := reflect.ValueOf(v2)
	for i := 0; i < s1.Len(); i++ {
		for j := 0; j < s2.Len(); j++ {
			// Combine using the given function.
			r = append(r, fn(s1.Index(i).Interface(), s2.Index(j).Interface()))
		}
	}
	return r
}

// pointersTo is a filter function that returns pointers.
func pointersTo(vs any) []any {
	return filter(vs, func(o any) (any, bool) {
		v := reflect.New(reflect.TypeOf(o))
		v.Elem().Set(reflect.ValueOf(o))
		return v.Interface(), true
	})
}

// interfacesTo is a filter function that returns interface objects.
func interfacesTo(vs any) []any {
	return filter(vs, func(o any) (any, bool) {
		var v [1]any
		v[0] = o
		return v, true
	})
}
