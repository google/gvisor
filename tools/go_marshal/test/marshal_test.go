// Copyright 2020 The gVisor Authors.
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

// Package marshal_test contains manual tests for the marshal interface. These
// are intended to test behaviour not covered by the automatically generated
// tests.
package marshal_test

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"reflect"
	"runtime"
	"testing"
	"unsafe"

	"github.com/google/go-cmp/cmp"
	"gvisor.dev/gvisor/pkg/marshal"
	"gvisor.dev/gvisor/pkg/marshal/primitive"
	"gvisor.dev/gvisor/pkg/syserror"
	"gvisor.dev/gvisor/pkg/usermem"
	"gvisor.dev/gvisor/tools/go_marshal/analysis"
	"gvisor.dev/gvisor/tools/go_marshal/test"
)

var simulatedErr error = syserror.EFAULT

// mockCopyContext implements marshal.CopyContext.
type mockCopyContext struct {
	taskMem usermem.BytesIO
}

// populate fills the task memory with the contents of val.
func (t *mockCopyContext) populate(val interface{}) {
	var buf bytes.Buffer
	// Use binary.Write so we aren't testing go-marshal against its own
	// potentially buggy implementation.
	if err := binary.Write(&buf, usermem.ByteOrder, val); err != nil {
		panic(err)
	}
	t.taskMem.Bytes = buf.Bytes()
}

func (t *mockCopyContext) setLimit(n int) {
	if len(t.taskMem.Bytes) < n {
		grown := make([]byte, n)
		copy(grown, t.taskMem.Bytes)
		t.taskMem.Bytes = grown
		return
	}
	t.taskMem.Bytes = t.taskMem.Bytes[:n]
}

// CopyScratchBuffer implements marshal.CopyContext.CopyScratchBuffer.
func (t *mockCopyContext) CopyScratchBuffer(size int) []byte {
	return make([]byte, size)
}

// CopyOutBytes implements marshal.CopyContext.CopyOutBytes. The implementation
// completely ignores the target address and stores a copy of b in its
// internally buffer, overriding any previous contents.
func (t *mockCopyContext) CopyOutBytes(_ usermem.Addr, b []byte) (int, error) {
	return t.taskMem.CopyOut(nil, 0, b, usermem.IOOpts{})
}

// CopyInBytes implements marshal.CopyContext.CopyInBytes. The implementation
// completely ignores the source address and always fills b from the begining of
// its internal buffer.
func (t *mockCopyContext) CopyInBytes(_ usermem.Addr, b []byte) (int, error) {
	return t.taskMem.CopyIn(nil, 0, b, usermem.IOOpts{})
}

// unsafeMemory returns the underlying memory for m. The returned slice is only
// valid for the lifetime for m. The garbage collector isn't aware that the
// returned slice is related to m, the caller must ensure m lives long enough.
func unsafeMemory(m marshal.Marshallable) []byte {
	if !m.Packed() {
		// We can't return a slice pointing to the underlying memory
		// since the layout isn't packed. Allocate a temporary buffer
		// and marshal instead.
		var buf bytes.Buffer
		if err := binary.Write(&buf, usermem.ByteOrder, m); err != nil {
			panic(err)
		}
		return buf.Bytes()
	}

	// reflect.ValueOf(m)
	//   .Elem() // Unwrap interface to inner concrete object
	//   .Addr() // Pointer value to object
	//   .Pointer() // Actual address from the pointer value
	ptr := reflect.ValueOf(m).Elem().Addr().Pointer()

	size := m.SizeBytes()

	var mem []byte
	hdr := (*reflect.SliceHeader)(unsafe.Pointer(&mem))
	hdr.Data = ptr
	hdr.Len = size
	hdr.Cap = size

	return mem
}

// unsafeMemorySlice returns the underlying memory for m. The returned slice is
// only valid for the lifetime for m. The garbage collector isn't aware that the
// returned slice is related to m, the caller must ensure m lives long enough.
//
// Precondition: m must be a slice.
func unsafeMemorySlice(m interface{}, elt marshal.Marshallable) []byte {
	kind := reflect.TypeOf(m).Kind()
	if kind != reflect.Slice {
		panic("unsafeMemorySlice called on non-slice")
	}

	if !elt.Packed() {
		// We can't return a slice pointing to the underlying memory
		// since the layout isn't packed. Allocate a temporary buffer
		// and marshal instead.
		var buf bytes.Buffer
		if err := binary.Write(&buf, usermem.ByteOrder, m); err != nil {
			panic(err)
		}
		return buf.Bytes()
	}

	v := reflect.ValueOf(m)
	length := v.Len() * elt.SizeBytes()

	var mem []byte
	hdr := (*reflect.SliceHeader)(unsafe.Pointer(&mem))
	hdr.Data = v.Pointer() // This is a pointer to the first elem for slices.
	hdr.Len = length
	hdr.Cap = length

	return mem
}

func isZeroes(buf []byte) bool {
	for _, b := range buf {
		if b != 0 {
			return false
		}
	}
	return true
}

// compareMemory compares the first n bytes of two chuncks of memory represented
// by expected and actual.
func compareMemory(t *testing.T, expected, actual []byte, n int) {
	t.Logf("Expected (%d): %v (%d) + (%d) %v\n", len(expected), expected[:n], n, len(expected)-n, expected[n:])
	t.Logf("Actual   (%d): %v (%d) + (%d) %v\n", len(actual), actual[:n], n, len(actual)-n, actual[n:])

	if diff := cmp.Diff(expected[:n], actual[:n]); diff != "" {
		t.Errorf("Memory buffers don't match:\n--- expected only\n+++ actual only\n%v", diff)
	}
}

// limitedCopyIn populates task memory with src, then unmarshals task memory to
// dst. The task signals an error at limit bytes during copy-in, which should
// result in a truncated unmarshalling.
func limitedCopyIn(t *testing.T, src, dst marshal.Marshallable, limit int) {
	var cc mockCopyContext
	cc.populate(src)
	cc.setLimit(limit)

	n, err := dst.CopyIn(&cc, usermem.Addr(0))
	if n != limit {
		t.Errorf("CopyIn copied unexpected number of bytes, expected %d, got %d", limit, n)
	}
	if err != simulatedErr {
		t.Errorf("CopyIn returned unexpected error, expected %v, got %v", simulatedErr, err)
	}

	expectedMem := unsafeMemory(src)
	defer runtime.KeepAlive(src)
	actualMem := unsafeMemory(dst)
	defer runtime.KeepAlive(dst)

	compareMemory(t, expectedMem, actualMem, n)

	// The last n bytes should be zero for actual, since actual was
	// zero-initialized, and CopyIn shouldn't have touched those bytes. However
	// we can only guarantee we didn't touch anything in the last n bytes if the
	// layout is packed.
	if dst.Packed() && !isZeroes(actualMem[n:]) {
		t.Errorf("Expected the last %d bytes of copied in object to be zeroes, got %v\n", dst.SizeBytes()-n, actualMem)
	}
}

// limitedCopyOut marshals src to task memory. The task signals an error at
// limit bytes during copy-out, which should result in a truncated marshalling.
func limitedCopyOut(t *testing.T, src marshal.Marshallable, limit int) {
	var cc mockCopyContext
	cc.setLimit(limit)

	n, err := src.CopyOut(&cc, usermem.Addr(0))
	if n != limit {
		t.Errorf("CopyOut copied unexpected number of bytes, expected %d, got %d", limit, n)
	}
	if err != simulatedErr {
		t.Errorf("CopyOut returned unexpected error, expected %v, got %v", simulatedErr, err)
	}

	expectedMem := unsafeMemory(src)
	defer runtime.KeepAlive(src)
	actualMem := cc.taskMem.Bytes

	compareMemory(t, expectedMem, actualMem, n)
}

// copyOutN marshals src to task memory, requesting the marshalling to be
// limited to limit bytes.
func copyOutN(t *testing.T, src marshal.Marshallable, limit int) {
	var cc mockCopyContext
	cc.setLimit(limit)

	n, err := src.CopyOutN(&cc, usermem.Addr(0), limit)
	if err != nil {
		t.Errorf("CopyOut returned unexpected error: %v", err)
	}
	if n != limit {
		t.Errorf("CopyOut copied unexpected number of bytes, expected %d, got %d", limit, n)
	}

	expectedMem := unsafeMemory(src)
	defer runtime.KeepAlive(src)
	actualMem := cc.taskMem.Bytes

	t.Logf("Expected: %v + %v\n", expectedMem[:n], expectedMem[n:])
	t.Logf("Actual  : %v + %v\n", actualMem[:n], actualMem[n:])

	compareMemory(t, expectedMem, actualMem, n)
}

// TestLimitedMarshalling verifies marshalling/unmarshalling succeeds when the
// underyling copy in/out operations partially succeed.
func TestLimitedMarshalling(t *testing.T) {
	types := []reflect.Type{
		// Packed types.
		reflect.TypeOf((*test.Type2)(nil)),
		reflect.TypeOf((*test.Type3)(nil)),
		reflect.TypeOf((*test.Timespec)(nil)),
		reflect.TypeOf((*test.Stat)(nil)),
		reflect.TypeOf((*test.InetAddr)(nil)),
		reflect.TypeOf((*test.SignalSet)(nil)),
		reflect.TypeOf((*test.SignalSetAlias)(nil)),
		// Non-packed types.
		reflect.TypeOf((*test.Type1)(nil)),
		reflect.TypeOf((*test.Type4)(nil)),
		reflect.TypeOf((*test.Type5)(nil)),
		reflect.TypeOf((*test.Type6)(nil)),
		reflect.TypeOf((*test.Type7)(nil)),
		reflect.TypeOf((*test.Type8)(nil)),
	}

	for _, tyPtr := range types {
		// Remove one level of pointer-indirection from the type. We get this
		// back when we pass the type to reflect.New.
		ty := tyPtr.Elem()

		// Partial copy-in.
		t.Run(fmt.Sprintf("PartialCopyIn_%v", ty), func(t *testing.T) {
			expected := reflect.New(ty).Interface().(marshal.Marshallable)
			actual := reflect.New(ty).Interface().(marshal.Marshallable)
			analysis.RandomizeValue(expected)

			limitedCopyIn(t, expected, actual, expected.SizeBytes()/2)
		})

		// Partial copy-out.
		t.Run(fmt.Sprintf("PartialCopyOut_%v", ty), func(t *testing.T) {
			expected := reflect.New(ty).Interface().(marshal.Marshallable)
			analysis.RandomizeValue(expected)

			limitedCopyOut(t, expected, expected.SizeBytes()/2)
		})

		// Explicitly request partial copy-out.
		t.Run(fmt.Sprintf("PartialCopyOutN_%v", ty), func(t *testing.T) {
			expected := reflect.New(ty).Interface().(marshal.Marshallable)
			analysis.RandomizeValue(expected)

			copyOutN(t, expected, expected.SizeBytes()/2)
		})
	}
}

// TestLimitedMarshalling verifies marshalling/unmarshalling of slices of
// marshallable types succeed when the underyling copy in/out operations
// partially succeed.
func TestLimitedSliceMarshalling(t *testing.T) {
	types := []struct {
		arrayPtrType reflect.Type
		copySliceIn  func(cc marshal.CopyContext, addr usermem.Addr, dstSlice interface{}) (int, error)
		copySliceOut func(cc marshal.CopyContext, addr usermem.Addr, srcSlice interface{}) (int, error)
		unsafeMemory func(arrPtr interface{}) []byte
	}{
		// Packed types.
		{
			reflect.TypeOf((*[20]test.Stat)(nil)),
			func(cc marshal.CopyContext, addr usermem.Addr, dst interface{}) (int, error) {
				slice := dst.(*[20]test.Stat)[:]
				return test.CopyStatSliceIn(cc, addr, slice)
			},
			func(cc marshal.CopyContext, addr usermem.Addr, src interface{}) (int, error) {
				slice := src.(*[20]test.Stat)[:]
				return test.CopyStatSliceOut(cc, addr, slice)
			},
			func(a interface{}) []byte {
				slice := a.(*[20]test.Stat)[:]
				return unsafeMemorySlice(slice, &slice[0])
			},
		},
		{
			reflect.TypeOf((*[1]test.Stat)(nil)),
			func(cc marshal.CopyContext, addr usermem.Addr, dst interface{}) (int, error) {
				slice := dst.(*[1]test.Stat)[:]
				return test.CopyStatSliceIn(cc, addr, slice)
			},
			func(cc marshal.CopyContext, addr usermem.Addr, src interface{}) (int, error) {
				slice := src.(*[1]test.Stat)[:]
				return test.CopyStatSliceOut(cc, addr, slice)
			},
			func(a interface{}) []byte {
				slice := a.(*[1]test.Stat)[:]
				return unsafeMemorySlice(slice, &slice[0])
			},
		},
		{
			reflect.TypeOf((*[5]test.SignalSetAlias)(nil)),
			func(cc marshal.CopyContext, addr usermem.Addr, dst interface{}) (int, error) {
				slice := dst.(*[5]test.SignalSetAlias)[:]
				return test.CopySignalSetAliasSliceIn(cc, addr, slice)
			},
			func(cc marshal.CopyContext, addr usermem.Addr, src interface{}) (int, error) {
				slice := src.(*[5]test.SignalSetAlias)[:]
				return test.CopySignalSetAliasSliceOut(cc, addr, slice)
			},
			func(a interface{}) []byte {
				slice := a.(*[5]test.SignalSetAlias)[:]
				return unsafeMemorySlice(slice, &slice[0])
			},
		},
		// Non-packed types.
		{
			reflect.TypeOf((*[20]test.Type1)(nil)),
			func(cc marshal.CopyContext, addr usermem.Addr, dst interface{}) (int, error) {
				slice := dst.(*[20]test.Type1)[:]
				return test.CopyType1SliceIn(cc, addr, slice)
			},
			func(cc marshal.CopyContext, addr usermem.Addr, src interface{}) (int, error) {
				slice := src.(*[20]test.Type1)[:]
				return test.CopyType1SliceOut(cc, addr, slice)
			},
			func(a interface{}) []byte {
				slice := a.(*[20]test.Type1)[:]
				return unsafeMemorySlice(slice, &slice[0])
			},
		},
		{
			reflect.TypeOf((*[1]test.Type1)(nil)),
			func(cc marshal.CopyContext, addr usermem.Addr, dst interface{}) (int, error) {
				slice := dst.(*[1]test.Type1)[:]
				return test.CopyType1SliceIn(cc, addr, slice)
			},
			func(cc marshal.CopyContext, addr usermem.Addr, src interface{}) (int, error) {
				slice := src.(*[1]test.Type1)[:]
				return test.CopyType1SliceOut(cc, addr, slice)
			},
			func(a interface{}) []byte {
				slice := a.(*[1]test.Type1)[:]
				return unsafeMemorySlice(slice, &slice[0])
			},
		},
		{
			reflect.TypeOf((*[7]test.Type8)(nil)),
			func(cc marshal.CopyContext, addr usermem.Addr, dst interface{}) (int, error) {
				slice := dst.(*[7]test.Type8)[:]
				return test.CopyType8SliceIn(cc, addr, slice)
			},
			func(cc marshal.CopyContext, addr usermem.Addr, src interface{}) (int, error) {
				slice := src.(*[7]test.Type8)[:]
				return test.CopyType8SliceOut(cc, addr, slice)
			},
			func(a interface{}) []byte {
				slice := a.(*[7]test.Type8)[:]
				return unsafeMemorySlice(slice, &slice[0])
			},
		},
	}

	for _, tt := range types {
		// The body of this loop is generic over the type tt.arrayPtrType, with
		// the help of reflection. To aid in readability, comments below show
		// the equivalent go code assuming
		// tt.arrayPtrType = typeof(*[20]test.Stat).

		// Equivalent:
		// var x *[20]test.Stat
		// arrayTy := reflect.TypeOf(*x)
		arrayTy := tt.arrayPtrType.Elem()

		// Partial copy-in of slices.
		t.Run(fmt.Sprintf("PartialCopySliceIn_%v", arrayTy), func(t *testing.T) {
			// Equivalent:
			// var x [20]test.Stat
			// length := len(x)
			length := arrayTy.Len()
			if length < 1 {
				panic("Test type can't be zero-length array")
			}
			// Equivalent:
			// elem := new(test.Stat).(marshal.Marshallable)
			elem := reflect.New(arrayTy.Elem()).Interface().(marshal.Marshallable)

			// Equivalent:
			// var expected, actual interface{}
			// expected = new([20]test.Stat)
			// actual = new([20]test.Stat)
			expected := reflect.New(arrayTy).Interface()
			actual := reflect.New(arrayTy).Interface()

			analysis.RandomizeValue(expected)

			limit := (length * elem.SizeBytes()) / 2
			// Also make sure the limit is partially inside one of the elements.
			limit += elem.SizeBytes() / 2
			analysis.RandomizeValue(expected)

			var cc mockCopyContext
			cc.populate(expected)
			cc.setLimit(limit)

			n, err := tt.copySliceIn(&cc, usermem.Addr(0), actual)
			if n != limit {
				t.Errorf("CopyIn copied unexpected number of bytes, expected %d, got %d", limit, n)
			}
			if n < length*elem.SizeBytes() && err != simulatedErr {
				t.Errorf("CopyIn returned unexpected error, expected %v, got %v", simulatedErr, err)
			}

			expectedMem := tt.unsafeMemory(expected)
			defer runtime.KeepAlive(expected)
			actualMem := tt.unsafeMemory(actual)
			defer runtime.KeepAlive(actual)

			compareMemory(t, expectedMem, actualMem, n)

			// The last n bytes should be zero for actual, since actual was
			// zero-initialized, and CopyIn shouldn't have touched those bytes. However
			// we can only guarantee we didn't touch anything in the last n bytes if the
			// layout is packed.
			if elem.Packed() && !isZeroes(actualMem[n:]) {
				t.Errorf("Expected the last %d bytes of copied in object to be zeroes, got %v\n", (elem.SizeBytes()*length)-n, actualMem)
			}
		})

		// Partial copy-out of slices.
		t.Run(fmt.Sprintf("PartialCopySliceOut_%v", arrayTy), func(t *testing.T) {
			// Equivalent:
			// var x [20]test.Stat
			// length := len(x)
			length := arrayTy.Len()
			if length < 1 {
				panic("Test type can't be zero-length array")
			}
			// Equivalent:
			// elem := new(test.Stat).(marshal.Marshallable)
			elem := reflect.New(arrayTy.Elem()).Interface().(marshal.Marshallable)

			// Equivalent:
			// var expected, actual interface{}
			// expected = new([20]test.Stat)
			// actual = new([20]test.Stat)
			expected := reflect.New(arrayTy).Interface()

			analysis.RandomizeValue(expected)

			limit := (length * elem.SizeBytes()) / 2
			// Also make sure the limit is partially inside one of the elements.
			limit += elem.SizeBytes() / 2
			analysis.RandomizeValue(expected)

			var cc mockCopyContext
			cc.populate(expected)
			cc.setLimit(limit)

			n, err := tt.copySliceOut(&cc, usermem.Addr(0), expected)
			if n != limit {
				t.Errorf("CopyIn copied unexpected number of bytes, expected %d, got %d", limit, n)
			}
			if n < length*elem.SizeBytes() && err != simulatedErr {
				t.Errorf("CopyIn returned unexpected error, expected %v, got %v", simulatedErr, err)
			}

			expectedMem := tt.unsafeMemory(expected)
			defer runtime.KeepAlive(expected)
			actualMem := cc.taskMem.Bytes

			compareMemory(t, expectedMem, actualMem, n)
		})
	}
}

func TestDynamicType(t *testing.T) {
	t12 := test.Type12Dynamic{
		X: 32,
		Y: []primitive.Int64{5, 6, 7},
	}

	var m marshal.Marshallable
	m = &t12 // Ensure that all methods were generated.
	b := make([]byte, m.SizeBytes())
	m.MarshalBytes(b)

	var res test.Type12Dynamic
	res.UnmarshalBytes(b)
	if !reflect.DeepEqual(t12, res) {
		t.Errorf("dynamic type is not same after marshalling and unmarshalling: before = %+v, after = %+v", t12, res)
	}
}
