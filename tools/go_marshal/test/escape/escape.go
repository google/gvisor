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

// Package escape contains test cases for escape analysis.
package escape

import (
	"gvisor.dev/gvisor/pkg/marshal"
	"gvisor.dev/gvisor/pkg/usermem"
	"gvisor.dev/gvisor/tools/go_marshal/test"
)

// dummyCopyContext implements marshal.CopyContext.
type dummyCopyContext struct {
}

func (*dummyCopyContext) CopyScratchBuffer(size int) []byte {
	return make([]byte, size)
}

func (*dummyCopyContext) CopyOutBytes(addr usermem.Addr, b []byte) (int, error) {
	return len(b), nil
}

func (*dummyCopyContext) CopyInBytes(addr usermem.Addr, b []byte) (int, error) {
	return len(b), nil
}

func (t *dummyCopyContext) MarshalBytes(addr usermem.Addr, marshallable marshal.Marshallable) {
	buf := t.CopyScratchBuffer(marshallable.SizeBytes())
	marshallable.MarshalBytes(buf)
	t.CopyOutBytes(addr, buf)
}

func (t *dummyCopyContext) MarshalUnsafe(addr usermem.Addr, marshallable marshal.Marshallable) {
	buf := t.CopyScratchBuffer(marshallable.SizeBytes())
	marshallable.MarshalUnsafe(buf)
	t.CopyOutBytes(addr, buf)
}

// +checkescape:all
//go:nosplit
func doCopyIn(t *dummyCopyContext) {
	var stat test.Stat
	stat.CopyIn(t, usermem.Addr(0xf000ba12))
}

// +checkescape:all
//go:nosplit
func doCopyOut(t *dummyCopyContext) {
	var stat test.Stat
	stat.CopyOut(t, usermem.Addr(0xf000ba12))
}

// +mustescape:builtin
// +mustescape:stack
//go:nosplit
func doMarshalBytesDirect(t *dummyCopyContext) {
	var stat test.Stat
	buf := t.CopyScratchBuffer(stat.SizeBytes())
	stat.MarshalBytes(buf)
	t.CopyOutBytes(usermem.Addr(0xf000ba12), buf)
}

// +mustescape:builtin
// +mustescape:stack
//go:nosplit
func doMarshalUnsafeDirect(t *dummyCopyContext) {
	var stat test.Stat
	buf := t.CopyScratchBuffer(stat.SizeBytes())
	stat.MarshalUnsafe(buf)
	t.CopyOutBytes(usermem.Addr(0xf000ba12), buf)
}

// +mustescape:local,heap
// +mustescape:stack
//go:nosplit
func doMarshalBytesViaMarshallable(t *dummyCopyContext) {
	var stat test.Stat
	t.MarshalBytes(usermem.Addr(0xf000ba12), &stat)
}

// +mustescape:local,heap
// +mustescape:stack
//go:nosplit
func doMarshalUnsafeViaMarshallable(t *dummyCopyContext) {
	var stat test.Stat
	t.MarshalUnsafe(usermem.Addr(0xf000ba12), &stat)
}
