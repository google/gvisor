// Copyright 2024 The gVisor Authors.
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

package aio

import (
	"unsafe"

	"golang.org/x/sys/unix"
)

// Request provides inputs to an asynchronous I/O operation.
type Request struct {
	ID  uint64 // copied to Completion.ID in the corresponding Completion
	Op  Op
	FD  int32          // host file descriptor
	Off int64          // offset into FD
	Buf unsafe.Pointer // depends on Op
	Len int            // depends on Op
}

// Read enqueues a read. The caller must ensure that the memory referred to by
// dst remains valid until the read is complete.
//
// Preconditions: As for q.Add().
func Read(q Queue, id uint64, fd int32, off int64, dst []byte) {
	q.Add(Request{
		ID:  id,
		Op:  OpRead,
		FD:  fd,
		Off: off,
		Buf: unsafe.Pointer(unsafe.SliceData(dst)),
		Len: len(dst),
	})
}

// Write enqueues a write. The caller must ensure that the memory referred to
// by src remains valid until the write is complete.
//
// Preconditions: As for q.Add().
func Write(q Queue, id uint64, fd int32, off int64, src []byte) {
	q.Add(Request{
		ID:  id,
		Op:  OpWrite,
		FD:  fd,
		Off: off,
		Buf: unsafe.Pointer(unsafe.SliceData(src)),
		Len: len(src),
	})
}

// Readv enqueues a vectored read. The caller must ensure that the struct iovec
// array referred to by dst, and the memory that those struct iovecs refer to,
// remain valid until the read is complete.
//
// Preconditions: As for q.Add().
func Readv(q Queue, id uint64, fd int32, off int64, dst []unix.Iovec) {
	q.Add(Request{
		ID:  id,
		Op:  OpReadv,
		FD:  fd,
		Off: off,
		Buf: unsafe.Pointer(unsafe.SliceData(dst)),
		Len: len(dst),
	})
}

// Writev enqueues a vectored write. The caller must ensure that the struct
// iovec array referred to by src, and the memory that those struct iovecs
// refer to, remain valid until the write is complete.
//
// Preconditions: As for q.Add().
func Writev(q Queue, id uint64, fd int32, off int64, src []unix.Iovec) {
	q.Add(Request{
		ID:  id,
		Op:  OpWritev,
		FD:  fd,
		Off: off,
		Buf: unsafe.Pointer(unsafe.SliceData(src)),
		Len: len(src),
	})
}
