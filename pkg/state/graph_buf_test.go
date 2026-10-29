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
	"bytes"
	"errors"
	"io"
	"math"
	"reflect"
	"testing"
	"unsafe"
)

func TestRuntimeTypeHelpers(t *testing.T) {
	for _, typ := range []reflect.Type{
		reflect.TypeFor[bool](),
		reflect.TypeFor[int64](),
		reflect.TypeFor[string](),
		reflect.TypeFor[*int](),
		reflect.TypeFor[[]byte](),
		reflect.TypeFor[[3]uint16](),
		reflect.TypeFor[map[string]int](),
		reflect.TypeFor[struct {
			a int32
			b string
		}](),
		reflect.TypeFor[any](),
		reflect.TypeFor[io.Reader](),
	} {
		rt := rtypeOf(typ)
		if rt == nil {
			t.Fatalf("rtypeOf(%v) = nil", typ)
		}
		if got := typeOfRtype(rt); got != typ {
			t.Fatalf("typeOfRtype(rtypeOf(%v)) = %v, want %v", typ, got, typ)
		}
	}

	x := 42
	var a any = &x
	ef := efaceOf(&a)
	if ef.typ != rtypeOf(reflect.TypeFor[*int]()) {
		t.Fatalf("efaceOf(&a).typ = %p, want %p", ef.typ, rtypeOf(reflect.TypeFor[*int]()))
	}
	if ef.data != unsafe.Pointer(&x) {
		t.Fatalf("efaceOf(&a).data = %p, want %p", ef.data, &x)
	}

	var arr [4]byte
	if got, want := add(unsafe.Pointer(&arr[0]), 3), unsafe.Pointer(&arr[3]); got != want {
		t.Fatalf("add(&arr[0], 3) = %p, want %p", got, want)
	}
}

func TestEncDecBufRoundTrip(t *testing.T) {
	var e encBuf
	e.grow(64)

	wantBytes := []byte{0x00, 0x01, 0x7f, 0x80, 0xff}
	for _, b := range wantBytes {
		e.byte(b)
	}

	wantUvarints := []uint64{
		0, 1, 0x7f, 0x80, 0x81, 0x3fff, 0x4000,
		1<<32 - 1, 1 << 32, math.MaxUint64 - 1, math.MaxUint64,
	}
	for _, v := range wantUvarints {
		e.uvarint(v)
	}

	wantVarints := []int64{
		0, 1, -1, 63, -64, 64, -65, 127, -128,
		math.MaxInt32, math.MinInt32, math.MaxInt64, math.MinInt64,
	}
	for _, v := range wantVarints {
		e.varint(v)
	}

	wantU32 := uint32(0x01020304)
	wantU64 := uint64(0x0102030405060708)
	e.uint32(wantU32)
	e.uint64(wantU64)

	wantSlice := []byte("raw-slice-payload")
	e.uvarint(uint64(len(wantSlice)))
	e.bytes(wantSlice)

	wantStrings := []string{"", "a", "hello, gVisor!"}
	for _, s := range wantStrings {
		e.string(s)
	}

	srcRaw := [2]uint64{0xdeadbeefcafebabe, 0x1122334455667788}
	e.raw(nil, 0)
	e.raw(unsafe.Pointer(&srcRaw), unsafe.Sizeof(srcRaw))

	// Encode a count of 3 elements with 2-byte payloads each.
	e.uvarint(3)
	e.bytes([]byte{1, 2, 3, 4, 5, 6})

	d := decBuf{b: e.b}

	for i, want := range wantBytes {
		if got := d.byte(); got != want {
			t.Fatalf("byte[%d] = %#x, want %#x", i, got, want)
		}
	}
	for i, want := range wantUvarints {
		if got := d.uvarint(); got != want {
			t.Fatalf("uvarint[%d] = %#x, want %#x", i, got, want)
		}
	}
	for i, want := range wantVarints {
		if got := d.varint(); got != want {
			t.Fatalf("varint[%d] = %d, want %d", i, got, want)
		}
	}
	if got := d.uint32(); got != wantU32 {
		t.Fatalf("uint32() = %#x, want %#x", got, wantU32)
	}
	if got := d.uint64(); got != wantU64 {
		t.Fatalf("uint64() = %#x, want %#x", got, wantU64)
	}

	n := d.byteLength()
	gotSlice := d.next(n)
	if !bytes.Equal(gotSlice, wantSlice) {
		t.Fatalf("next(%d) = %q, want %q", n, gotSlice, wantSlice)
	}
	if cap(gotSlice) != len(gotSlice) {
		t.Fatalf("next(%d) cap = %d, want clipped cap %d", n, cap(gotSlice), len(gotSlice))
	}

	for i, want := range wantStrings {
		strLen := d.byteLength()
		if got := string(d.next(strLen)); got != want {
			t.Fatalf("string[%d] = %q, want %q", i, got, want)
		}
	}

	var dstRaw [2]uint64
	d.raw(nil, 0)
	d.raw(unsafe.Pointer(&dstRaw), unsafe.Sizeof(dstRaw))
	if dstRaw != srcRaw {
		t.Fatalf("raw() = %#x, want %#x", dstRaw, srcRaw)
	}

	if gotCount := d.count(2); gotCount != 3 {
		t.Fatalf("count(2) = %d, want 3", gotCount)
	}
	if gotTail := d.next(6); !bytes.Equal(gotTail, []byte{1, 2, 3, 4, 5, 6}) {
		t.Fatalf("tail = %v, want [1 2 3 4 5 6]", gotTail)
	}
	if d.pos != len(d.b) {
		t.Fatalf("unread bytes remaining: pos=%d, len=%d", d.pos, len(d.b))
	}
}

func assertTruncated(t *testing.T, name string, fn func()) {
	t.Helper()
	err := safely(fn)
	if err == nil {
		t.Fatalf("%s succeeded, want errTruncated", name)
	}
	if !errors.As(err, new(errTruncated)) {
		t.Fatalf("%s failed with %v, want errTruncated", name, err)
	}
}

func assertStateFail(t *testing.T, name string, fn func()) {
	t.Helper()
	err := safely(fn)
	if err == nil {
		t.Fatalf("%s succeeded, want failure", name)
	}
	if errors.As(err, new(errTruncated)) {
		t.Fatalf("%s failed with errTruncated (%v), want Failf error", name, err)
	}
}

func TestDecBufErrors(t *testing.T) {
	assertTruncated(t, "empty byte", func() {
		d := decBuf{}
		_ = d.byte()
	})
	assertTruncated(t, "empty uvarint", func() {
		d := decBuf{}
		_ = d.uvarint()
	})
	assertTruncated(t, "unfinished multi-byte uvarint", func() {
		d := decBuf{b: []byte{0x80, 0x80}}
		_ = d.uvarint()
	})
	assertTruncated(t, "byteLength beyond remaining", func() {
		var e encBuf
		e.uvarint(5)
		e.bytes([]byte{1, 2})
		d := decBuf{b: e.b}
		_ = d.byteLength()
	})
	assertTruncated(t, "short uint32", func() {
		d := decBuf{b: []byte{1, 2, 3}}
		_ = d.uint32()
	})
	assertTruncated(t, "short uint64", func() {
		d := decBuf{b: []byte{1, 2, 3, 4, 5, 6, 7}}
		_ = d.uint64()
	})
	assertTruncated(t, "next negative", func() {
		d := decBuf{b: []byte{1, 2}}
		_ = d.next(-1)
	})
	assertTruncated(t, "next beyond remaining", func() {
		d := decBuf{b: []byte{1, 2}}
		_ = d.next(3)
	})
	assertTruncated(t, "raw beyond remaining", func() {
		var dst uint32
		d := decBuf{b: []byte{1, 2}}
		d.raw(unsafe.Pointer(&dst), unsafe.Sizeof(dst))
	})

	assertStateFail(t, "uvarint overflow (>64 bits)", func() {
		// 10 continuation bytes + final byte >= 2 overflows uint64.
		b := bytes.Repeat([]byte{0x80}, 10)
		b = append(b, 0x02)
		d := decBuf{b: b}
		_ = d.uvarint()
	})
	assertStateFail(t, "count with invalid minBytes", func() {
		var e encBuf
		e.uvarint(0)
		d := decBuf{b: e.b}
		_ = d.count(0)
	})
	assertStateFail(t, "count exceeding remaining bytes", func() {
		var e encBuf
		e.uvarint(3)
		e.bytes([]byte{1, 2, 3, 4, 5})
		d := decBuf{b: e.b}
		_ = d.count(2)
	})
}
