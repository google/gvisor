// Copyright 2026 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package state

import (
	"context"
	"math/rand"
	"reflect"
	"testing"
	"unsafe"
)

func TestSliceOfArraysInteriorPointer(t *testing.T) {
	elemTI := typeInfoOf(reflect.TypeFor[[2]int]())
	ptrElemTI := typeInfoOf(reflect.TypeFor[[2][2]int]())

	t.Run("SliceThenPtr", func(t *testing.T) {
		s := make([][2]int, 3)
		p := (*[2][2]int)(s[0:2])
		es := newGraphEncodeState(context.Background(), elemTI)
		defer es.release()
		es.sliceTarget(unsafe.Pointer(unsafe.SliceData(s)), elemTI, uintptr(len(s)), uintptr(cap(s)))
		es.ptrTarget(unsafe.Pointer(p), ptrElemTI)
	})

	t.Run("PtrThenSlice", func(t *testing.T) {
		s := make([][2]int, 3)
		p := (*[2][2]int)(s[0:2])
		es := newGraphEncodeState(context.Background(), elemTI)
		defer es.release()
		es.ptrTarget(unsafe.Pointer(p), ptrElemTI)
		es.sliceTarget(unsafe.Pointer(unsafe.SliceData(s)), elemTI, uintptr(len(s)), uintptr(cap(s)))
	})

	t.Run("SameRangeSliceThenPtrThenOverlappingSlice", func(t *testing.T) {
		backing := make([][2]int, 3)
		s1 := backing[0:2:2]
		p := (*[2][2]int)(s1)
		s2 := backing[1:3:3]
		es := newGraphEncodeState(context.Background(), elemTI)
		defer es.release()
		es.sliceTarget(unsafe.Pointer(unsafe.SliceData(s1)), elemTI, uintptr(len(s1)), uintptr(cap(s1)))
		es.ptrTarget(unsafe.Pointer(p), ptrElemTI)
		es.sliceTarget(unsafe.Pointer(unsafe.SliceData(s2)), elemTI, uintptr(len(s2)), uintptr(cap(s2)))
	})

	t.Run("AllPermutationsOverlappingArrayPtrAndSlices", func(t *testing.T) {
		type stepKind int
		const (
			stepS1 stepKind = iota
			stepPtr
			stepS2
		)
		perms := [][]stepKind{
			{stepS1, stepPtr, stepS2},
			{stepS1, stepS2, stepPtr},
			{stepPtr, stepS1, stepS2},
			{stepPtr, stepS2, stepS1},
			{stepS2, stepS1, stepPtr},
			{stepS2, stepPtr, stepS1},
			{stepPtr, stepS2},
			{stepS2, stepPtr},
		}
		for _, perm := range perms {
			backing := make([][2]int, 3)
			s1 := backing[0:2:2]
			p := (*[2][2]int)(s1)
			s2 := backing[1:3:3]
			es := newGraphEncodeState(context.Background(), elemTI)
			for _, st := range perm {
				switch st {
				case stepS1:
					es.sliceTarget(unsafe.Pointer(unsafe.SliceData(s1)), elemTI, uintptr(len(s1)), uintptr(cap(s1)))
				case stepPtr:
					es.ptrTarget(unsafe.Pointer(p), ptrElemTI)
				case stepS2:
					es.sliceTarget(unsafe.Pointer(unsafe.SliceData(s2)), elemTI, uintptr(len(s2)), uintptr(cap(s2)))
				}
			}
			es.release()
		}
	})

	t.Run("OverlappingArrayPointersOnly", func(t *testing.T) {
		backing := make([][2]int, 3)
		p1 := (*[2][2]int)(backing[0:2])
		p2 := (*[2][2]int)(backing[1:3])
		es := newGraphEncodeState(context.Background(), elemTI)
		defer es.release()
		es.ptrTarget(unsafe.Pointer(p1), ptrElemTI)
		es.ptrTarget(unsafe.Pointer(p2), ptrElemTI)
	})
}

func TestAddrMap(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	for _, initial := range []int{0, 1, 1000} {
		var m addrMap
		if initial > 0 {
			m.init(initial)
		}
		want := make(map[uintptr]int32)
		for round := 0; round < 3; round++ {
			for i := 0; i < 5000; i++ {
				// Use clustered keys, like addresses, and zero.
				k := uintptr(r.Intn(20000)) * 8
				if i%3 == 0 {
					k = uintptr(r.Uint64())
				}
				if k == ^uintptr(0) {
					continue
				}
				v := int32(r.Intn(1 << 30))
				m.set(k, v)
				want[k] = v
			}
			for k, v := range want {
				if got, ok := m.get(k); !ok || got != v {
					t.Fatalf("get(%#x) = %d, %t, want %d, true", k, got, ok, v)
				}
			}
			for i := 0; i < 1000; i++ {
				k := uintptr(r.Intn(40000))*8 + 4
				got, gotOK := m.get(k)
				wantV, wantOK := want[k]
				if got != wantV || gotOK != wantOK {
					t.Fatalf("get(%#x) = (%d, %t), want (%d, %t)", k, got, gotOK, wantV, wantOK)
				}
			}
			if m.n != len(want) {
				t.Fatalf("got %d entries, want %d", m.n, len(want))
			}
			m.reset()
			clear(want)
			if _, ok := m.get(8); ok {
				t.Fatalf("get after reset found a key")
			}
			if _, ok := m.get(^uintptr(0)); ok {
				t.Fatalf("get(max uintptr) unexpectedly succeeded")
			}
		}
	}

	var m addrMap
	m.set(0, 7)
	func() {
		defer func() {
			if recover() == nil {
				t.Fatalf("set(max uintptr) did not fail")
			}
		}()
		m.set(^uintptr(0), 1)
	}()
	if got, ok := m.get(0); !ok || got != 7 {
		t.Fatalf("get(0) = %d, %t, want 7, true", got, ok)
	}
}
