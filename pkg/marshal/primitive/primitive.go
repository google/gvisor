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

	"gvisor.dev/gvisor/pkg/marshal"
	"gvisor.dev/gvisor/pkg/usermem"
)

// Int8 is a marshal.Marshallable implementation for int8.
//
// +marshal slice:Int8Slice:inner
type Int8 int8

// Uint8 is a marshal.Marshallable implementation for uint8.
//
// +marshal slice:Uint8Slice:inner
type Uint8 uint8

// Int16 is a marshal.Marshallable implementation for int16.
//
// +marshal slice:Int16Slice:inner
type Int16 int16

// Uint16 is a marshal.Marshallable implementation for uint16.
//
// +marshal slice:Uint16Slice:inner
type Uint16 uint16

// Int32 is a marshal.Marshallable implementation for int32.
//
// +marshal slice:Int32Slice:inner
type Int32 int32

// Uint32 is a marshal.Marshallable implementation for uint32.
//
// +marshal slice:Uint32Slice:inner
type Uint32 uint32

// Int64 is a marshal.Marshallable implementation for int64.
//
// +marshal slice:Int64Slice:inner
type Int64 int64

// Uint64 is a marshal.Marshallable implementation for uint64.
//
// +marshal slice:Uint64Slice:inner
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
func (b *ByteSlice) MarshalBytes(dst []byte) {
	copy(dst, *b)
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (b *ByteSlice) UnmarshalBytes(src []byte) {
	copy(*b, src)
}

// Packed implements marshal.Marshallable.Packed.
func (b *ByteSlice) Packed() bool {
	return false
}

// MarshalUnsafe implements marshal.Marshallable.MarshalUnsafe.
func (b *ByteSlice) MarshalUnsafe(dst []byte) {
	b.MarshalBytes(dst)
}

// UnmarshalUnsafe implements marshal.Marshallable.UnmarshalUnsafe.
func (b *ByteSlice) UnmarshalUnsafe(src []byte) {
	b.UnmarshalBytes(src)
}

// CopyIn implements marshal.Marshallable.CopyIn.
func (b *ByteSlice) CopyIn(task marshal.Task, addr usermem.Addr) (int, error) {
	return task.CopyInBytes(addr, *b)
}

// CopyOut implements marshal.Marshallable.CopyOut.
func (b *ByteSlice) CopyOut(task marshal.Task, addr usermem.Addr) (int, error) {
	return task.CopyOutBytes(addr, *b)
}

// CopyOutN implements marshal.Marshallable.CopyOutN.
func (b *ByteSlice) CopyOutN(task marshal.Task, addr usermem.Addr, limit int) (int, error) {
	return task.CopyOutBytes(addr, (*b)[:limit])
}

// WriteTo implements io.WriterTo.WriteTo.
func (b *ByteSlice) WriteTo(w io.Writer) (int64, error) {
	n, err := w.Write(*b)
	return int64(n), err
}

var _ marshal.Marshallable = (*ByteSlice)(nil)

// Below, we define some convenience functions for marshalling primitive types
// using the newtypes above, without requiring superfluous casts.

// 16-bit integers

// CopyInt16In is a convenient wrapper for copying in an int16 from the task's
// memory.
func CopyInt16In(task marshal.Task, addr usermem.Addr, dst *int16) (int, error) {
	var buf Int16
	n, err := buf.CopyIn(task, addr)
	if err != nil {
		return n, err
	}
	*dst = int16(buf)
	return n, nil
}

// CopyInt16Out is a convenient wrapper for copying out an int16 to the task's
// memory.
func CopyInt16Out(task marshal.Task, addr usermem.Addr, src int16) (int, error) {
	srcP := Int16(src)
	return srcP.CopyOut(task, addr)
}

// CopyUint16In is a convenient wrapper for copying in a uint16 from the task's
// memory.
func CopyUint16In(task marshal.Task, addr usermem.Addr, dst *uint16) (int, error) {
	var buf Uint16
	n, err := buf.CopyIn(task, addr)
	if err != nil {
		return n, err
	}
	*dst = uint16(buf)
	return n, nil
}

// CopyUint16Out is a convenient wrapper for copying out a uint16 to the task's
// memory.
func CopyUint16Out(task marshal.Task, addr usermem.Addr, src uint16) (int, error) {
	srcP := Uint16(src)
	return srcP.CopyOut(task, addr)
}

// 32-bit integers

// CopyInt32In is a convenient wrapper for copying in an int32 from the task's
// memory.
func CopyInt32In(task marshal.Task, addr usermem.Addr, dst *int32) (int, error) {
	var buf Int32
	n, err := buf.CopyIn(task, addr)
	if err != nil {
		return n, err
	}
	*dst = int32(buf)
	return n, nil
}

// CopyInt32Out is a convenient wrapper for copying out an int32 to the task's
// memory.
func CopyInt32Out(task marshal.Task, addr usermem.Addr, src int32) (int, error) {
	srcP := Int32(src)
	return srcP.CopyOut(task, addr)
}

// CopyUint32In is a convenient wrapper for copying in a uint32 from the task's
// memory.
func CopyUint32In(task marshal.Task, addr usermem.Addr, dst *uint32) (int, error) {
	var buf Uint32
	n, err := buf.CopyIn(task, addr)
	if err != nil {
		return n, err
	}
	*dst = uint32(buf)
	return n, nil
}

// CopyUint32Out is a convenient wrapper for copying out a uint32 to the task's
// memory.
func CopyUint32Out(task marshal.Task, addr usermem.Addr, src uint32) (int, error) {
	srcP := Uint32(src)
	return srcP.CopyOut(task, addr)
}

// 64-bit integers

// CopyInt64In is a convenient wrapper for copying in an int64 from the task's
// memory.
func CopyInt64In(task marshal.Task, addr usermem.Addr, dst *int64) (int, error) {
	var buf Int64
	n, err := buf.CopyIn(task, addr)
	if err != nil {
		return n, err
	}
	*dst = int64(buf)
	return n, nil
}

// CopyInt64Out is a convenient wrapper for copying out an int64 to the task's
// memory.
func CopyInt64Out(task marshal.Task, addr usermem.Addr, src int64) (int, error) {
	srcP := Int64(src)
	return srcP.CopyOut(task, addr)
}

// CopyUint64In is a convenient wrapper for copying in a uint64 from the task's
// memory.
func CopyUint64In(task marshal.Task, addr usermem.Addr, dst *uint64) (int, error) {
	var buf Uint64
	n, err := buf.CopyIn(task, addr)
	if err != nil {
		return n, err
	}
	*dst = uint64(buf)
	return n, nil
}

// CopyUint64Out is a convenient wrapper for copying out a uint64 to the task's
// memory.
func CopyUint64Out(task marshal.Task, addr usermem.Addr, src uint64) (int, error) {
	srcP := Uint64(src)
	return srcP.CopyOut(task, addr)
}
