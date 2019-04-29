// Copyright 2018 The gVisor Authors.
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

package fs

import (
	"gvisor.googlesource.com/gvisor/pkg/sentry/arch"
	"gvisor.googlesource.com/gvisor/pkg/sentry/context"
	"gvisor.googlesource.com/gvisor/pkg/sentry/memmap"
	"gvisor.googlesource.com/gvisor/pkg/sentry/usermem"
	"gvisor.googlesource.com/gvisor/pkg/waiter"
)

// FileOperations are operations on a File that diverge per file system.
//
// Operations that take a *File may use only the following interfaces:
//
// - File.UniqueID:	Operations may only read this value.
// - File.Dirent:	Operations must not take or drop a reference.
// - File.Offset(): 	This value is guaranteed to not change for the
//			duration of the operation.
// - File.Flags():	This value may change during the operation.
type FileOperations interface {
	// Release release resources held by FileOperations.
	Release()

	// Waitable defines how this File can be waited on for read and
	// write readiness.
	waiter.Waitable

	// Seek seeks to offset based on SeekWhence. Returns the new
	// offset or no change in the offset and an error.
	Seek(ctx context.Context, file *File, whence SeekWhence, offset int64) (int64, error)

	// Readdir reads the directory entries of file and serializes them
	// using serializer.
	//
	// Returns the new directory offset or no change in the offset and
	// an error. The offset returned must not be less than file.Offset().
	//
	// Serialization of directory entries must not happen asynchronously.
	Readdir(ctx context.Context, file *File, serializer DentrySerializer) (int64, error)

	// Read reads from file into dst at offset and returns the number
	// of bytes read which must be greater than or equal to 0. File
	// systems that do not support reading at an offset, (i.e. pipefs,
	// sockfs) may ignore the offset. These file systems are expected
	// to construct Files with !FileFlags.Pread.
	//
	// Read may return a nil error and only partially fill dst (at or
	// before EOF). If the file represents a symlink, Read reads the target
	// value of the symlink.
	//
	// Read does not check permissions nor flags.
	//
	// Read must not be called if !FileFlags.Read.
	Read(ctx context.Context, file *File, dst usermem.IOSequence, offset int64) (int64, error)

	// Write writes src to file at offset and returns the number of bytes
	// written which must be greater than or equal to 0. Like Read, file
	// systems that do not support writing at an offset (i.e. pipefs, sockfs)
	// may ignore the offset. These file systems are expected to construct
	// Files with !FileFlags.Pwrite.
	//
	// If only part of src could be written, Write must return an error
	// indicating why (e.g. syserror.ErrWouldBlock).
	//
	// Write does not check permissions nor flags.
	//
	// Write must not be called if !FileFlags.Write.
	Write(ctx context.Context, file *File, src usermem.IOSequence, offset int64) (int64, error)

	// Fsync writes buffered modifications of file and/or flushes in-flight
	// operations to backing storage based on syncType. The range to sync is
	// [start, end]. The end is inclusive so that the last byte of a maximally
	// sized file can be synced.
	Fsync(ctx context.Context, file *File, start, end int64, syncType SyncType) error

	// Flush this file's buffers/state (on close(2)).
	Flush(ctx context.Context, file *File) error

	// ConfigureMMap mutates opts to implement mmap(2) for the file. Most
	// implementations can either embed fsutil.FileNoMMap (if they don't support
	// memory mapping) or call fsutil.GenericConfigureMMap with the appropriate
	// memmap.Mappable.
	ConfigureMMap(ctx context.Context, file *File, opts *memmap.MMapOpts) error

	// UnstableAttr returns the "unstable" attributes of the inode represented
	// by the file. Most implementations can embed
	// fsutil.FileUseInodeUnstableAttr, which delegates to
	// InodeOperations.UnstableAttr.
	UnstableAttr(ctx context.Context, file *File) (UnstableAttr, error)

	// Ioctl implements the ioctl(2) linux syscall.
	//
	// io provides access to the virtual memory space to which pointers in args
	// refer.
	//
	// Preconditions: The AddressSpace (if any) that io refers to is activated.
	Ioctl(ctx context.Context, io usermem.IO, args arch.SyscallArguments) (uintptr, error)
}
