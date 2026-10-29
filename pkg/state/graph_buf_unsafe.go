// Copyright 2026 The gVisor Authors.
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

package state

import (
	"encoding/binary"
	"math"
	"reflect"
	"slices"
	"unsafe"
)

// eface is the runtime representation of an empty interface.
type eface struct {
	typ  unsafe.Pointer
	data unsafe.Pointer
}

// iface is the runtime representation of a non-empty interface.
type iface struct {
	tab  unsafe.Pointer
	data unsafe.Pointer
}

const (
	_ = unsafe.Sizeof(eface{})        // +checksize internal/abi EmptyInterface
	_ = unsafe.Offsetof(eface{}.typ)  // +checkoffset internal/abi EmptyInterface.Type
	_ = unsafe.Offsetof(eface{}.data) // +checkoffset internal/abi EmptyInterface.Data
	_ = unsafe.Sizeof(iface{})        // +checksize internal/abi NonEmptyInterface
	_ = unsafe.Offsetof(iface{}.tab)  // +checkoffset internal/abi NonEmptyInterface.ITab
	_ = unsafe.Offsetof(iface{}.data) // +checkoffset internal/abi NonEmptyInterface.Data
)

// sliceHeader is the runtime representation of a slice.
type sliceHeader struct {
	data unsafe.Pointer
	len  int
	cap  int
}

// efaceOf returns the runtime representation of *v.
func efaceOf(v *any) *eface {
	return (*eface)(unsafe.Pointer(v))
}

// rtypeOf returns the runtime type descriptor of t, which is the type word of
// interfaces holding values of type t.
func rtypeOf(t reflect.Type) unsafe.Pointer {
	// The dynamic value of a reflect.Type is a *reflect.rtype, which points to
	// the runtime type descriptor.
	return (*iface)(unsafe.Pointer(&t)).data
}

// typeOfRtype returns the reflect.Type for a runtime type descriptor.
func typeOfRtype(rt unsafe.Pointer) reflect.Type {
	var v any
	efaceOf(&v).typ = rt
	return reflect.TypeOf(v)
}

// add returns p+off.
func add(p unsafe.Pointer, off uintptr) unsafe.Pointer {
	return unsafe.Add(p, off)
}

// zeroSized is the address used for pointers to zero-sized values that are
// not within another object.
var zeroSized [1]byte

// encBuf is an append-only output buffer.
type encBuf struct {
	b []byte
}

// grow ensures that n more bytes can be appended without reallocation.
func (e *encBuf) grow(n int) {
	e.b = slices.Grow(e.b, n)
}

func (e *encBuf) byte(v byte) {
	e.b = append(e.b, v)
}

func (e *encBuf) uvarint(v uint64) {
	if v < 0x80 {
		e.b = append(e.b, byte(v))
		return
	}
	e.b = binary.AppendUvarint(e.b, v)
}

func (e *encBuf) varint(v int64) {
	u := uint64(v) << 1
	if v < 0 {
		u = ^u
	}
	e.uvarint(u)
}

func (e *encBuf) uint32(v uint32) {
	e.b = binary.LittleEndian.AppendUint32(e.b, v)
}

func (e *encBuf) uint64(v uint64) {
	e.b = binary.LittleEndian.AppendUint64(e.b, v)
}

func (e *encBuf) bytes(p []byte) {
	e.b = append(e.b, p...)
}

func (e *encBuf) string(s string) {
	e.uvarint(uint64(len(s)))
	e.b = append(e.b, s...)
}

// raw appends n bytes of memory at p.
func (e *encBuf) raw(p unsafe.Pointer, n uintptr) {
	if n == 0 {
		return
	}
	e.b = append(e.b, unsafe.Slice((*byte)(p), n)...)
}

// decBuf is an input buffer. Reads past the end panic, which Load reports as
// an error.
type decBuf struct {
	b   []byte
	pos int
}

// errTruncated is the error for reads beyond the end of the input.
type errTruncated struct{}

func (errTruncated) Error() string { return "state data truncated" }

func (d *decBuf) truncated() {
	panic(errTruncated{})
}

func (d *decBuf) byte() byte {
	if d.pos >= len(d.b) {
		d.truncated()
	}
	v := d.b[d.pos]
	d.pos++
	return v
}

func (d *decBuf) uvarint() uint64 {
	if d.pos < len(d.b) {
		if v := d.b[d.pos]; v < 0x80 {
			d.pos++
			return uint64(v)
		}
	}
	v, n := binary.Uvarint(d.b[d.pos:])
	if n <= 0 {
		if n == 0 {
			d.truncated()
		}
		Failf("varint overflow")
	}
	d.pos += n
	return v
}

func (d *decBuf) varint() int64 {
	u := d.uvarint()
	v := int64(u >> 1)
	if u&1 != 0 {
		v = ^v
	}
	return v
}

// byteLength reads a length of bytes that follow in the input.
func (d *decBuf) byteLength() int {
	v := d.uvarint()
	if v > uint64(len(d.b)-d.pos) {
		d.truncated()
	}
	return int(v)
}

// count reads a number of elements, each of which is encoded in at least
// minBytes bytes.
func (d *decBuf) count(minBytes int) int {
	if minBytes < 1 {
		Failf("invalid minimum element size %d", minBytes)
	}
	v := d.uvarint()
	if v > math.MaxInt32 || v > uint64((len(d.b)-d.pos)/minBytes) {
		Failf("invalid count %d with %d bytes remaining", v, len(d.b)-d.pos)
	}
	return int(v)
}

func (d *decBuf) uint32() uint32 {
	if len(d.b)-d.pos < 4 {
		d.truncated()
	}
	v := binary.LittleEndian.Uint32(d.b[d.pos:])
	d.pos += 4
	return v
}

func (d *decBuf) uint64() uint64 {
	if len(d.b)-d.pos < 8 {
		d.truncated()
	}
	v := binary.LittleEndian.Uint64(d.b[d.pos:])
	d.pos += 8
	return v
}

// next returns the next n bytes.
func (d *decBuf) next(n int) []byte {
	if n < 0 || len(d.b)-d.pos < n {
		d.truncated()
	}
	v := d.b[d.pos : d.pos+n : d.pos+n]
	d.pos += n
	return v
}

// raw copies n bytes to memory at p.
func (d *decBuf) raw(p unsafe.Pointer, n uintptr) {
	if n == 0 {
		return
	}
	copy(unsafe.Slice((*byte)(p), n), d.next(int(n)))
}
