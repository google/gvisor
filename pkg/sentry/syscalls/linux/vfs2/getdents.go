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

package vfs2

import (
	"fmt"

	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/syserror"
)

// Getdents implements Linux syscall getdents(2).
func Getdents(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	return getdents(t, args, false /* isGetdents64 */)
}

// Getdents64 implements Linux syscall getdents64(2).
func Getdents64(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	return getdents(t, args, true /* isGetdents64 */)
}

func getdents(t *kernel.Task, args arch.SyscallArguments, isGetdents64 bool) (uintptr, *kernel.SyscallControl, error) {
	fd := args[0].Int()
	addr := args[1].Pointer()
	size := int(args[2].Uint())

	file := t.GetFileVFS2(fd)
	if file == nil {
		return 0, nil, syserror.EBADF
	}
	defer file.DecRef(t)

	cb := getGetdentsCallback(t, addr, size, isGetdents64)
	err := file.IterDirents(t, cb)
	n := size - cb.remaining
	putGetdentsCallback(cb)
	if n == 0 {
		return 0, nil, err
	}
	return uintptr(n), nil, nil
}

type getdentsCallback struct {
	t            *kernel.Task
	addr         hostarch.Addr
	remaining    int
	isGetdents64 bool
}

var getdentsCallbackPool = sync.Pool{
	New: func() interface{} {
		return &getdentsCallback{}
	},
}

func getGetdentsCallback(t *kernel.Task, addr hostarch.Addr, size int, isGetdents64 bool) *getdentsCallback {
	cb := getdentsCallbackPool.Get().(*getdentsCallback)
	*cb = getdentsCallback{
		t:            t,
		addr:         addr,
		remaining:    size,
		isGetdents64: isGetdents64,
	}
	return cb
}

func putGetdentsCallback(cb *getdentsCallback) {
	cb.t = nil
	getdentsCallbackPool.Put(cb)
}

// Handle implements vfs.IterDirentsCallback.Handle.
func (cb *getdentsCallback) Handle(dirent vfs.Dirent) error {
	var buf []byte
	if cb.isGetdents64 {
		// struct linux_dirent64 {
		//     ino64_t        d_ino;    /* 64-bit inode number */
		//     off64_t        d_off;    /* 64-bit offset to next structure */
		//     unsigned short d_reclen; /* Size of this dirent */
		//     unsigned char  d_type;   /* File type */
		//     char           d_name[]; /* Filename (null-terminated) */
		// };
		size := 8 + 8 + 2 + 1 + 1 + len(dirent.Name)
		size = (size + 7) &^ 7 // round up to multiple of 8
		if size > cb.remaining {
			return linuxerr.EINVAL
		}
		buf = cb.t.CopyScratchBuffer(size)
		hostarch.ByteOrder.PutUint64(buf[0:8], dirent.Ino)
		hostarch.ByteOrder.PutUint64(buf[8:16], uint64(dirent.NextOff))
		hostarch.ByteOrder.PutUint16(buf[16:18], uint16(size))
		buf[18] = dirent.Type
		copy(buf[19:], dirent.Name)
		// Zero out all remaining bytes in buf, including the NUL terminator
		// after dirent.Name.
		bufTail := buf[19+len(dirent.Name):]
		for i := range bufTail {
			bufTail[i] = 0
		}
	} else {
		// struct linux_dirent {
		//     unsigned long  d_ino;     /* Inode number */
		//     unsigned long  d_off;     /* Offset to next linux_dirent */
		//     unsigned short d_reclen;  /* Length of this linux_dirent */
		//     char           d_name[];  /* Filename (null-terminated) */
		//                       /* length is actually (d_reclen - 2 -
		//                          offsetof(struct linux_dirent, d_name)) */
		//     /*
		//     char           pad;       // Zero padding byte
		//     char           d_type;    // File type (only since Linux
		//                               // 2.6.4); offset is (d_reclen - 1)
		//     */
		// };
		if cb.t.Arch().Width() != 8 {
			panic(fmt.Sprintf("unsupported sizeof(unsigned long): %d", cb.t.Arch().Width()))
		}
		size := 8 + 8 + 2 + 1 + 1 + len(dirent.Name)
		size = (size + 7) &^ 7 // round up to multiple of sizeof(long)
		if size > cb.remaining {
			return linuxerr.EINVAL
		}
		buf = cb.t.CopyScratchBuffer(size)
		hostarch.ByteOrder.PutUint64(buf[0:8], dirent.Ino)
		hostarch.ByteOrder.PutUint64(buf[8:16], uint64(dirent.NextOff))
		hostarch.ByteOrder.PutUint16(buf[16:18], uint16(size))
		copy(buf[18:], dirent.Name)
		// Zero out all remaining bytes in buf, including the NUL terminator
		// after dirent.Name and the zero padding byte between the name and
		// dirent type.
		bufTail := buf[18+len(dirent.Name) : size-1]
		for i := range bufTail {
			bufTail[i] = 0
		}
		buf[size-1] = dirent.Type
	}
	n, err := cb.t.CopyOutBytes(cb.addr, buf)
	if err != nil {
		// Don't report partially-written dirents by advancing cb.addr or
		// cb.remaining.
		return err
	}
	cb.addr += hostarch.Addr(n)
	cb.remaining -= n
	return nil
}
