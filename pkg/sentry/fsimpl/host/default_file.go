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

package host

import (
	"math"
	"syscall"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/fd"
	"gvisor.dev/gvisor/pkg/safemem"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/syserror"
	"gvisor.dev/gvisor/pkg/usermem"
)

// defaultFileFD implements FileDescriptionImpl for non-socket, non-TTY files.
type defaultFileFD struct {
	fileDescription

	// canMap specifies whether we allow the file to be memory mapped.
	canMap bool

	// mu protects the fields below.
	mu sync.Mutex

	// offset specifies the current file offset.
	offset int64
}

// TODO(gvisor.dev/issue/1672): Implement Waitable interface.

// PRead implements FileDescriptionImpl.
func (f *defaultFileFD) PRead(ctx context.Context, dst usermem.IOSequence, offset int64, opts vfs.ReadOptions) (int64, error) {
	// TODO(b/34716638): Some char devices do support offsets, e.g. /dev/null.
	if f.inode.isStream {
		return 0, syserror.ESPIPE
	}

	return readFromHostFD(ctx, f.inode.hostFD, dst, offset, int(opts.Flags))
}

// Read implements FileDescriptionImpl.
func (f *defaultFileFD) Read(ctx context.Context, dst usermem.IOSequence, opts vfs.ReadOptions) (int64, error) {
	// TODO(b/34716638): Some char devices do support offsets, e.g. /dev/null.
	if f.inode.isStream {
		// These files can't be memory mapped, assert this.
		if f.canMap {
			panic("files that can return EWOULDBLOCK (sockets, pipes, etc.) cannot be memory mapped")
		}

		n, err := readFromHostFD(ctx, f.inode.hostFD, dst, -1, int(opts.Flags))
		if isBlockError(err) {
			// If we got any data at all, return it as a "completed" partial read
			// rather than retrying until complete.
			if n != 0 {
				err = nil
			} else {
				err = syserror.ErrWouldBlock
			}
		}
		return n, err
	}
	// TODO(gvisor.dev/issue/1672): Cache pages, when forced to do so.
	f.mu.Lock()
	n, err := readFromHostFD(ctx, f.inode.hostFD, dst, f.offset, int(opts.Flags))
	f.offset += n
	f.mu.Unlock()
	return n, err
}

func readFromHostFD(ctx context.Context, hostFD int, dst usermem.IOSequence, offset int64, flags int) (int64, error) {
	// TODO(gvisor.dev/issue/1672): Support select preadv2 flags.
	if flags != 0 {
		return 0, syserror.EOPNOTSUPP
	}

	var reader safemem.Reader
	if offset == -1 {
		reader = safemem.FromIOReader{fd.NewReadWriter(hostFD)}
	} else {
		reader = safemem.FromVecReaderFunc{
			func(srcs [][]byte) (int64, error) {
				n, err := unix.Preadv(hostFD, srcs, offset)
				return int64(n), err
			},
		}
	}
	n, err := dst.CopyOutFrom(ctx, reader)
	return int64(n), err
}

// PWrite implements FileDescriptionImpl.
func (f *defaultFileFD) PWrite(ctx context.Context, src usermem.IOSequence, offset int64, opts vfs.WriteOptions) (int64, error) {
	// TODO(b/34716638): Some char devices do support offsets, e.g. /dev/null.
	if f.inode.isStream {
		return 0, syserror.ESPIPE
	}

	return writeToHostFD(ctx, f.inode.hostFD, src, offset, int(opts.Flags))
}

// Write implements FileDescriptionImpl.
func (f *defaultFileFD) Write(ctx context.Context, src usermem.IOSequence, opts vfs.WriteOptions) (int64, error) {
	// TODO(b/34716638): Some char devices do support offsets, e.g. /dev/null.
	if f.inode.isStream {
		// These files can't be memory mapped, assert this.
		if f.canMap {
			panic("files that can return EWOULDBLOCK (sockets, pipes, etc.) cannot be memory mapped")
		}

		n, err := writeToHostFD(ctx, f.inode.hostFD, src, -1, int(opts.Flags))
		if isBlockError(err) {
			err = syserror.ErrWouldBlock
		}
		return n, err
	}
	// TODO(gvisor.dev/issue/1672): Cache pages, when forced to do so.
	// TODO(gvisor.dev/issue/1672): Write to end of file and update offset if O_APPEND is set on this file.
	f.mu.Lock()
	n, err := writeToHostFD(ctx, f.inode.hostFD, src, f.offset, int(opts.Flags))
	f.offset += n
	f.mu.Unlock()
	return n, err
}

func writeToHostFD(ctx context.Context, hostFD int, src usermem.IOSequence, offset int64, flags int) (int64, error) {
	// TODO(gvisor.dev/issue/1672): Support select pwritev2 flags.
	if flags != 0 {
		return 0, syserror.EOPNOTSUPP
	}

	var writer safemem.Writer
	if offset == -1 {
		writer = safemem.FromIOWriter{fd.NewReadWriter(hostFD)}
	} else {
		writer = safemem.FromVecWriterFunc{
			func(srcs [][]byte) (int64, error) {
				n, err := unix.Pwritev(hostFD, srcs, offset)
				return int64(n), err
			},
		}
	}
	n, err := src.CopyInTo(ctx, writer)
	return int64(n), err
}

// Seek implements FileDescriptionImpl.
//
// Note that we do not support seeking on directories, since we do not even
// allow directory fds to be imported at all.
func (f *defaultFileFD) Seek(_ context.Context, offset int64, whence int32) (int64, error) {
	// TODO(b/34716638): Some char devices do support seeking, e.g. /dev/null.
	if f.inode.isStream {
		return 0, syserror.ESPIPE
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	switch whence {
	case linux.SEEK_SET:
		if offset < 0 {
			return f.offset, syserror.EINVAL
		}
		f.offset = offset

	case linux.SEEK_CUR:
		// Check for overflow. Note that underflow cannot occur, since f.offset >= 0.
		if offset > math.MaxInt64-f.offset {
			return f.offset, syserror.EOVERFLOW
		}
		if f.offset+offset < 0 {
			return f.offset, syserror.EINVAL
		}
		f.offset += offset

	case linux.SEEK_END:
		var s syscall.Stat_t
		if err := syscall.Fstat(f.inode.hostFD, &s); err != nil {
			return f.offset, err
		}
		size := s.Size

		// Check for overflow. Note that underflow cannot occur, since size >= 0.
		if offset > math.MaxInt64-size {
			return f.offset, syserror.EOVERFLOW
		}
		if size+offset < 0 {
			return f.offset, syserror.EINVAL
		}
		f.offset = size + offset

	case linux.SEEK_DATA, linux.SEEK_HOLE:
		// Modifying the offset in the host file table should not matter, since
		// this is the only place where we use it.
		//
		// For reading and writing, we always rely on our internal offset.
		n, err := unix.Seek(f.inode.hostFD, offset, int(whence))
		if err != nil {
			return f.offset, err
		}
		f.offset = n

	default:
		// Invalid whence.
		return f.offset, syserror.EINVAL
	}

	return f.offset, nil
}

// Sync implements FileDescriptionImpl.
func (f *defaultFileFD) Sync(context.Context) error {
	// TODO(gvisor.dev/issue/1672): Currently we do not support the SyncData optimization, so we always sync everything.
	return unix.Fsync(f.inode.hostFD)
}

// ConfigureMMap implements FileDescriptionImpl.
func (f *defaultFileFD) ConfigureMMap(_ context.Context, opts *memmap.MMapOpts) error {
	if !f.canMap {
		return syserror.ENODEV
	}
	// TODO(gvisor.dev/issue/1672): Implement ConfigureMMap and Mappable interface.
	return syserror.ENODEV
}
