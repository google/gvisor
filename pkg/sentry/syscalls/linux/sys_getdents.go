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

package linux

import (
	"fmt"

	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/usermem"
)

// Getdents implements Linux syscall getdents(2).
func Getdents(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	return getdents(t, args, false /* isGetdents64 */)
}

// Getdents64 implements Linux syscall getdents64(2).
func Getdents64(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	return getdents(t, args, true /* isGetdents64 */)
}

// DirentStructBytesWithoutName is enough to fit (struct linux_dirent) and
// (struct linux_dirent64) without accounting for the name parameter.
const DirentStructBytesWithoutName = 8 + 8 + 2 + 1 + 1

func getdents(t *kernel.Task, args arch.SyscallArguments, isGetdents64 bool) (uintptr, *kernel.SyscallControl, error) {
	fd := args[0].Int()
	addr := args[1].Pointer()
	size := int(args[2].Uint())
	if size < DirentStructBytesWithoutName {
		return 0, nil, linuxerr.EINVAL
	}

	file := t.GetFile(fd)
	if file == nil {
		return 0, nil, linuxerr.EBADF
	}
	defer file.DecRef(t)

	// We want to be sure of the allowed buffer size before calling IterDirents,
	// because this function depends on IterDirents saving state of which dirent
	// was the last one that was successfully operated on.
	allowedSize, err := t.MemoryManager().EnsurePMAsExist(t, addr, int64(size), usermem.IOOpts{
		AddressSpaceActive: true,
	})
	if allowedSize == 0 {
		return 0, nil, err
	}

	cb := getGetdentsCallback(t, int(allowedSize), size, isGetdents64)
	err = file.IterDirents(t, cb)
	n, _ := t.CopyOutBytes(addr, cb.buf[:cb.copied])

	putGetdentsCallback(cb)

	// Only report an error in case we didn't copy anything.
	// If we did manage to give _something_ to the caller then the correct
	// behaviour is to return success.
	if n == 0 {
		return 0, nil, err
	}

	return uintptr(n), nil, nil
}

type getdentsCallback struct {
	t                *kernel.Task
	buf              []byte
	copied           int
	userReportedSize int
	isGetdents64     bool
}

var getdentsCallbackPool = sync.Pool{
	New: func() any {
		return &getdentsCallback{}
	},
}

func getGetdentsCallback(t *kernel.Task, size int, userReportedSize int, isGetdents64 bool) *getdentsCallback {
	cb := getdentsCallbackPool.Get().(*getdentsCallback)
	buf := cb.buf
	if cap(buf) < size {
		buf = make([]byte, size)
	} else {
		buf = buf[:size]
	}

	*cb = getdentsCallback{
		t:                t,
		buf:              buf,
		copied:           0,
		userReportedSize: userReportedSize,
		isGetdents64:     isGetdents64,
	}
	return cb
}

func putGetdentsCallback(cb *getdentsCallback) {
	cb.t = nil
	cb.buf = cb.buf[:0]
	getdentsCallbackPool.Put(cb)
}

// Handle implements vfs.IterDirentsCallback.Handle.
func (cb *getdentsCallback) Handle(dirent vfs.Dirent) error {
	remaining := len(cb.buf) - cb.copied
	if cb.isGetdents64 {
		// struct linux_dirent64 {
		//     ino64_t        d_ino;    /* 64-bit inode number */
		//     off64_t        d_off;    /* 64-bit offset to next structure */
		//     unsigned short d_reclen; /* Size of this dirent */
		//     unsigned char  d_type;   /* File type */
		//     char           d_name[]; /* Filename (null-terminated) */
		// };
		size := DirentStructBytesWithoutName + len(dirent.Name)
		size = (size + 7) &^ 7 // round up to multiple of 8
		if size > remaining {
			// This is only needed to imitate Linux, since it writes out to the user
			// as it's iterating over dirs. We don't do that because we can't take
			// the mm.mappingMu while holding the filesystem mutex.
			if cb.copied == 0 && cb.userReportedSize >= size {
				return linuxerr.EFAULT
			}
			return linuxerr.EINVAL
		}
		buf := cb.buf[cb.copied : cb.copied+size]
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
		cb.copied += size
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
		size := DirentStructBytesWithoutName + len(dirent.Name)
		size = (size + 7) &^ 7 // round up to multiple of sizeof(long)
		if size > remaining {
			if cb.copied == 0 && cb.userReportedSize >= size {
				return linuxerr.EFAULT
			}
			return linuxerr.EINVAL
		}
		buf := cb.buf[cb.copied : cb.copied+size]
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
		cb.copied += size
	}

	return nil
}
