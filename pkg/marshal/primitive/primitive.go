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

// Package primitive defines marshal.Marshallable implementations for primitive
// types.
package primitive

import (
	"io"

	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/marshal"
)

// Int8 is a marshal.Marshallable implementation for int8.
//
// +marshal boundCheck slice:Int8Slice:inner
type Int8 int8

// Uint8 is a marshal.Marshallable implementation for uint8.
//
// +marshal boundCheck slice:Uint8Slice:inner
type Uint8 uint8

// Int16 is a marshal.Marshallable implementation for int16.
//
// +marshal boundCheck slice:Int16Slice:inner
type Int16 int16

// Uint16 is a marshal.Marshallable implementation for uint16.
//
// +marshal boundCheck slice:Uint16Slice:inner
type Uint16 uint16

// Int32 is a marshal.Marshallable implementation for int32.
//
// +marshal boundCheck slice:Int32Slice:inner
type Int32 int32

// Uint32 is a marshal.Marshallable implementation for uint32.
//
// +marshal boundCheck slice:Uint32Slice:inner
type Uint32 uint32

// Int64 is a marshal.Marshallable implementation for int64.
//
// +marshal boundCheck slice:Int64Slice:inner
type Int64 int64

// Uint64 is a marshal.Marshallable implementation for uint64.
//
// +marshal boundCheck slice:Uint64Slice:inner
type Uint64 uint64

// ByteSlice is a marshal.Marshallable implementation for []byte.
// This is a convenience wrapper around a dynamically sized type, and can't be
// embedded in other marshallable types because it breaks assumptions made by
// go-marshal internals. It violates the "no dynamically-sized types"
// constraint of the go-marshal library.
type ByteSlice []byte

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (b *ByteSlice) SizeBytes() int {
	return len(*b)
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (b *ByteSlice) MarshalBytes(dst []byte) []byte {
	return dst[copy(dst, *b):]
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (b *ByteSlice) UnmarshalBytes(src []byte) []byte {
	return src[copy(*b, src):]
}

// Packed implements marshal.Marshallable.Packed.
func (b *ByteSlice) Packed() bool {
	return false
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (b *ByteSlice) MarshalUnsafe(dst []byte) []byte {
	return b.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (b *ByteSlice) UnmarshalUnsafe(src []byte) []byte {
	return b.UnmarshalBytes(src)
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (b *ByteSlice) CopyIn(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
	return cc.CopyInBytes(addr, *b)
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (b *ByteSlice) CopyOut(cc marshal.CopyContext, addr hostarch.Addr) (int, error) {
	return cc.CopyOutBytes(addr, *b)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (b *ByteSlice) CopyOutN(cc marshal.CopyContext, addr hostarch.Addr, limit int) (int, error) {
	return cc.CopyOutBytes(addr, (*b)[:limit])
}

// WriteTo implements io.WriterTo.WriteTo.
func (b *ByteSlice) WriteTo(w io.Writer) (int64, error) {
	n, err := w.Write(*b)
	return int64(n), err
}

var _ marshal.Marshallable = (*ByteSlice)(nil)

// The following set of functions are convenient shorthands for wrapping a
// built-in type in a marshallable primitive type. For example:
//
// func useMarshallable(m marshal.Marshallable) { ... }
//
// // Compare:
//
// buf = []byte{...}
// // useMarshallable(&primitive.ByteSlice(buf)) // Not allowed, can't address temp value.
// bufP := primitive.ByteSlice(buf)
// useMarshallable(&bufP)
//
// // Vs:
//
// useMarshallable(AsByteSlice(buf))
//
// Note that the argument to these function escapes, so avoid using them on very
// hot code paths. But generally if a function accepts an interface as an
// argument, the argument escapes anyways.

// AllocateInt8 returns x as a marshallable.
func AllocateInt8(x int8) marshal.Marshallable {
	p := Int8(x)
	return &p
}

// AllocateUint8 returns x as a marshallable.
func AllocateUint8(x uint8) marshal.Marshallable {
	p := Uint8(x)
	return &p
}

// AllocateInt16 returns x as a marshallable.
func AllocateInt16(x int16) marshal.Marshallable {
	p := Int16(x)
	return &p
}

// AllocateUint16 returns x as a marshallable.
func AllocateUint16(x uint16) marshal.Marshallable {
	p := Uint16(x)
	return &p
}

// AllocateInt32 returns x as a marshallable.
func AllocateInt32(x int32) marshal.Marshallable {
	p := Int32(x)
	return &p
}

// AllocateUint32 returns x as a marshallable.
func AllocateUint32(x uint32) marshal.Marshallable {
	p := Uint32(x)
	return &p
}

// AllocateInt64 returns x as a marshallable.
func AllocateInt64(x int64) marshal.Marshallable {
	p := Int64(x)
	return &p
}

// AllocateUint64 returns x as a marshallable.
func AllocateUint64(x uint64) marshal.Marshallable {
	p := Uint64(x)
	return &p
}

// AsByteSlice returns b as a marshallable. Note that this allocates a new slice
// header, but does not copy the slice contents.
func AsByteSlice(b []byte) marshal.Marshallable {
	bs := ByteSlice(b)
	return &bs
}

// Below, we define some convenience functions for marshalling primitive types
// using the newtypes above, without requiring superfluous casts.

// 8-bit integers

// CopyInt8In is a convenient wrapper for copying in an int8 from the task's
// memory.
func CopyInt8In(cc marshal.CopyContext, addr hostarch.Addr, dst *int8) (int, error) {
	var buf Int8
	n, err := buf.CopyIn(cc, addr)
	if err != nil {
		return n, err
	}
	*dst = int8(buf)
	return n, nil
}

// CopyInt8Out is a convenient wrapper for copying out an int8 to the task's
// memory.
func CopyInt8Out(cc marshal.CopyContext, addr hostarch.Addr, src int8) (int, error) {
	srcP := Int8(src)
	return srcP.CopyOut(cc, addr)
}

// CopyUint8In is a convenient wrapper for copying in a uint8 from the task's
// memory.
func CopyUint8In(cc marshal.CopyContext, addr hostarch.Addr, dst *uint8) (int, error) {
	var buf Uint8
	n, err := buf.CopyIn(cc, addr)
	if err != nil {
		return n, err
	}
	*dst = uint8(buf)
	return n, nil
}

// CopyUint8Out is a convenient wrapper for copying out a uint8 to the task's
// memory.
func CopyUint8Out(cc marshal.CopyContext, addr hostarch.Addr, src uint8) (int, error) {
	srcP := Uint8(src)
	return srcP.CopyOut(cc, addr)
}

// 16-bit integers

// CopyInt16In is a convenient wrapper for copying in an int16 from the task's
// memory.
func CopyInt16In(cc marshal.CopyContext, addr hostarch.Addr, dst *int16) (int, error) {
	var buf Int16
	n, err := buf.CopyIn(cc, addr)
	if err != nil {
		return n, err
	}
	*dst = int16(buf)
	return n, nil
}

// CopyInt16Out is a convenient wrapper for copying out an int16 to the task's
// memory.
func CopyInt16Out(cc marshal.CopyContext, addr hostarch.Addr, src int16) (int, error) {
	srcP := Int16(src)
	return srcP.CopyOut(cc, addr)
}

// CopyUint16In is a convenient wrapper for copying in a uint16 from the task's
// memory.
func CopyUint16In(cc marshal.CopyContext, addr hostarch.Addr, dst *uint16) (int, error) {
	var buf Uint16
	n, err := buf.CopyIn(cc, addr)
	if err != nil {
		return n, err
	}
	*dst = uint16(buf)
	return n, nil
}

// CopyUint16Out is a convenient wrapper for copying out a uint16 to the task's
// memory.
func CopyUint16Out(cc marshal.CopyContext, addr hostarch.Addr, src uint16) (int, error) {
	srcP := Uint16(src)
	return srcP.CopyOut(cc, addr)
}

// 32-bit integers

// CopyInt32In is a convenient wrapper for copying in an int32 from the task's
// memory.
func CopyInt32In(cc marshal.CopyContext, addr hostarch.Addr, dst *int32) (int, error) {
	var buf Int32
	n, err := buf.CopyIn(cc, addr)
	if err != nil {
		return n, err
	}
	*dst = int32(buf)
	return n, nil
}

// CopyInt32Out is a convenient wrapper for copying out an int32 to the task's
// memory.
func CopyInt32Out(cc marshal.CopyContext, addr hostarch.Addr, src int32) (int, error) {
	srcP := Int32(src)
	return srcP.CopyOut(cc, addr)
}

// CopyUint32In is a convenient wrapper for copying in a uint32 from the task's
// memory.
func CopyUint32In(cc marshal.CopyContext, addr hostarch.Addr, dst *uint32) (int, error) {
	var buf Uint32
	n, err := buf.CopyIn(cc, addr)
	if err != nil {
		return n, err
	}
	*dst = uint32(buf)
	return n, nil
}

// CopyUint32Out is a convenient wrapper for copying out a uint32 to the task's
// memory.
func CopyUint32Out(cc marshal.CopyContext, addr hostarch.Addr, src uint32) (int, error) {
	srcP := Uint32(src)
	return srcP.CopyOut(cc, addr)
}

// 64-bit integers

// CopyInt64In is a convenient wrapper for copying in an int64 from the task's
// memory.
func CopyInt64In(cc marshal.CopyContext, addr hostarch.Addr, dst *int64) (int, error) {
	var buf Int64
	n, err := buf.CopyIn(cc, addr)
	if err != nil {
		return n, err
	}
	*dst = int64(buf)
	return n, nil
}

// CopyInt64Out is a convenient wrapper for copying out an int64 to the task's
// memory.
func CopyInt64Out(cc marshal.CopyContext, addr hostarch.Addr, src int64) (int, error) {
	srcP := Int64(src)
	return srcP.CopyOut(cc, addr)
}

// CopyUint64In is a convenient wrapper for copying in a uint64 from the task's
// memory.
func CopyUint64In(cc marshal.CopyContext, addr hostarch.Addr, dst *uint64) (int, error) {
	var buf Uint64
	n, err := buf.CopyIn(cc, addr)
	if err != nil {
		return n, err
	}
	*dst = uint64(buf)
	return n, nil
}

// CopyUint64Out is a convenient wrapper for copying out a uint64 to the task's
// memory.
func CopyUint64Out(cc marshal.CopyContext, addr hostarch.Addr, src uint64) (int, error) {
	srcP := Uint64(src)
	return srcP.CopyOut(cc, addr)
}

// CopyByteSliceIn is a convenient wrapper for copying in a []byte from the
// task's memory.
func CopyByteSliceIn(cc marshal.CopyContext, addr hostarch.Addr, dst *[]byte) (int, error) {
	var buf ByteSlice
	n, err := buf.CopyIn(cc, addr)
	if err != nil {
		return n, err
	}
	*dst = []byte(buf)
	return n, nil
}

// CopyByteSliceOut is a convenient wrapper for copying out a []byte to the
// task's memory.
func CopyByteSliceOut(cc marshal.CopyContext, addr hostarch.Addr, src []byte) (int, error) {
	srcP := ByteSlice(src)
	return srcP.CopyOut(cc, addr)
}

// CopyStringIn is a convenient wrapper for copying in a string from the
// task's memory.
func CopyStringIn(cc marshal.CopyContext, addr hostarch.Addr, dst *string) (int, error) {
	var buf ByteSlice
	n, err := buf.CopyIn(cc, addr)
	if err != nil {
		return n, err
	}
	*dst = string(buf)
	return n, nil
}

// CopyStringOut is a convenient wrapper for copying out a string to the task's
// memory.
func CopyStringOut(cc marshal.CopyContext, addr hostarch.Addr, src string) (int, error) {
	srcP := ByteSlice(src)
	return srcP.CopyOut(cc, addr)
}
