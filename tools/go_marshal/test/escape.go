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

// This binary provides a convienient target for analyzing how the go-marshal
// API causes its various arguments to escape to the heap. To use, build and
// observe the output from the go compiler's escape analysis:
//
// $ bazel build :escape
// ...
// escape.go:67:2: moved to heap: task
// escape.go:77:31: make([]byte, size) escapes to heap
// escape.go:87:31: make([]byte, size) escapes to heap
// escape.go:96:6: moved to heap: stat
// ...
//
// This is not an automated test, but simply a minimal binary for easy analysis.
package main

import (
	"gvisor.dev/gvisor/pkg/usermem"
	"gvisor.dev/gvisor/tools/go_marshal/marshal"
	"gvisor.dev/gvisor/tools/go_marshal/test"
)

// dummyTask implements marshal.Task.
type dummyTask struct {
}

func (*dummyTask) CopyScratchBuffer(size int) []byte {
	return make([]byte, size)
}

func (*dummyTask) CopyOutBytes(addr usermem.Addr, b []byte) (int, error) {
	return len(b), nil
}

func (*dummyTask) CopyInBytes(addr usermem.Addr, b []byte) (int, error) {
	return len(b), nil
}

func (task *dummyTask) MarshalBytes(addr usermem.Addr, marshallable marshal.Marshallable) {
	buf := task.CopyScratchBuffer(marshallable.SizeBytes())
	marshallable.MarshalBytes(buf)
	task.CopyOutBytes(addr, buf)
}

func (task *dummyTask) MarshalUnsafe(addr usermem.Addr, marshallable marshal.Marshallable) {
	buf := task.CopyScratchBuffer(marshallable.SizeBytes())
	marshallable.MarshalUnsafe(buf)
	task.CopyOutBytes(addr, buf)
}

// Expected escapes:
// - task: passed to marshal.Marshallable.CopyOut as the marshal.Task interface.
func doCopyOut() {
	task := dummyTask{}
	var stat test.Stat
	stat.CopyOut(&task, usermem.Addr(0xf000ba12))
}

// Expected escapes:
// - buf: make allocates on the heap.
func doMarshalBytesDirect() {
	task := dummyTask{}
	var stat test.Stat
	buf := task.CopyScratchBuffer(stat.SizeBytes())
	stat.MarshalBytes(buf)
	task.CopyOutBytes(usermem.Addr(0xf000ba12), buf)
}

// Expected escapes:
// - buf: make allocates on the heap.
func doMarshalUnsafeDirect() {
	task := dummyTask{}
	var stat test.Stat
	buf := task.CopyScratchBuffer(stat.SizeBytes())
	stat.MarshalUnsafe(buf)
	task.CopyOutBytes(usermem.Addr(0xf000ba12), buf)
}

// Expected escapes:
// - stat: passed to dummyTask.MarshalBytes as the marshal.Marshallable interface.
func doMarshalBytesViaMarshallable() {
	task := dummyTask{}
	var stat test.Stat
	task.MarshalBytes(usermem.Addr(0xf000ba12), &stat)
}

// Expected escapes:
// - stat: passed to dummyTask.MarshalUnsafe as the marshal.Marshallable interface.
func doMarshalUnsafeViaMarshallable() {
	task := dummyTask{}
	var stat test.Stat
	task.MarshalUnsafe(usermem.Addr(0xf000ba12), &stat)
}

func main() {
	doCopyOut()
	doMarshalBytesDirect()
	doMarshalUnsafeDirect()
	doMarshalBytesViaMarshallable()
	doMarshalUnsafeViaMarshallable()
}
