// Copyright 2018 Google LLC
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

// SpliceOpts define how a splice works.
type SpliceOpts struct {
	// Length is the length of the splice operation.
	Length int64

	// SrcOffset indicates whether the existing source file offset should
	// be used. If this is true, then the Start value below is used.
	//
	// When passed to FileOperations object, this should always be true as
	// the offset will be provided by a layer above, unless the object in
	// question is a pipe or socket. This value can be relied upon for such
	// an indicator.
	SrcOffset bool

	// SrcStart is the start of the source file. This is used only if
	// SrcOffset is false.
	SrcStart int64

	// Dup indicates that the contents should not be consumed from the
	// source (e.g. in the case of a socket or a pipe), but duplicated.
	Dup bool

	// DstOffset indicates that the destination file offset should be used.
	//
	// See SrcOffset for additional information.
	DstOffset bool

	// DstStart is the start of the destination file. This is used only if
	// DstOffset is false.
	DstStart int64
}

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

	// WriteTo is a variant of read that takes a another file as a
	// destination. Note that this is called before ReadFrom, and hence
	// favored.
	//
	// The same preconditions as Read apply.
	WriteTo(ctx context.Context, file *File, dst *File, opts SpliceOpts) (int64, error)

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

	// ReadFrom is a variant of write that takes a another file as a
	// destination. Note that this is called after WriteTo, and is thus
	// less favored.
	//
	// The same preconditions as Write apply; FileFlags.Write must be set.
	ReadFrom(ctx context.Context, file *File, src *File, opts SpliceOpts) (int64, error)

	// Fsync writes buffered modifications of file and/or flushes in-flight
	// operations to backing storage based on syncType. The range to sync is
	// [start, end]. The end is inclusive so that the last byte of a maximally
	// sized file can be synced.
	Fsync(ctx context.Context, file *File, start, end int64, syncType SyncType) error

	// Flush this file's buffers/state (on close(2)).
	Flush(ctx context.Context, file *File) error

	// ConfigureMMap mutates opts to implement mmap(2) for the file. Most
	// implementations can either embed fsutil.NoMMap (if they don't support
	// memory mapping) or call fsutil.GenericConfigureMMap with the appropriate
	// memmap.Mappable.
	ConfigureMMap(ctx context.Context, file *File, opts *memmap.MMapOpts) error

	// Ioctl implements the ioctl(2) linux syscall.
	//
	// io provides access to the virtual memory space to which pointers in args
	// refer.
	//
	// Preconditions: The AddressSpace (if any) that io refers to is activated.
	Ioctl(ctx context.Context, io usermem.IO, args arch.SyscallArguments) (uintptr, error)
}
