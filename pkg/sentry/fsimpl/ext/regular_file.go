// Copyright 2019 The gVisor Authors.
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

package ext

import (
	"io"
	"sync"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/sentry/context"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/safemem"
	"gvisor.dev/gvisor/pkg/sentry/usermem"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/syserror"
)

// regularFile represents a regular file's inode. This too follows the
// inheritance pattern prevelant in the vfs layer described in
// pkg/sentry/vfs/README.md.
type regularFile struct {
	inode inode

	// This is immutable. The first field of fileReader implementations must be
	// regularFile to ensure temporality.
	// io.ReaderAt is more strict than io.Reader in the sense that a partial read
	// is always accompanied by an error. If a read spans past the end of file, a
	// partial read (within file range) is done and io.EOF is returned.
	impl io.ReaderAt
}

// newRegularFile is the regularFile constructor. It figures out what kind of
// file this is and initializes the fileReader.
func newRegularFile(inode inode) (*regularFile, error) {
	regFile := regularFile{
		inode: inode,
	}

	inodeFlags := inode.diskInode.Flags()

	if inodeFlags.Extents {
		file, err := newExtentFile(regFile)
		if err != nil {
			return nil, err
		}

		file.regFile.inode.impl = &file.regFile
		return &file.regFile, nil
	}

	file, err := newBlockMapFile(regFile)
	if err != nil {
		return nil, err
	}
	file.regFile.inode.impl = &file.regFile
	return &file.regFile, nil
}

func (in *inode) isRegular() bool {
	_, ok := in.impl.(*regularFile)
	return ok
}

// directoryFD represents a directory file description. It implements
// vfs.FileDescriptionImpl.
type regularFileFD struct {
	fileDescription

	// off is the file offset. off is accessed using atomic memory operations.
	off int64

	// offMu serializes operations that may mutate off.
	offMu sync.Mutex
}

// Release implements vfs.FileDescriptionImpl.Release.
func (fd *regularFileFD) Release() {}

// PRead implements vfs.FileDescriptionImpl.PRead.
func (fd *regularFileFD) PRead(ctx context.Context, dst usermem.IOSequence, offset int64, opts vfs.ReadOptions) (int64, error) {
	safeReader := safemem.FromIOReaderAt{
		ReaderAt: fd.inode().impl.(*regularFile).impl,
		Offset:   offset,
	}

	// Copies data from disk directly into usermem without any intermediate
	// allocations (if dst is converted into BlockSeq such that it does not need
	// safe copying).
	return dst.CopyOutFrom(ctx, safeReader)
}

// Read implements vfs.FileDescriptionImpl.Read.
func (fd *regularFileFD) Read(ctx context.Context, dst usermem.IOSequence, opts vfs.ReadOptions) (int64, error) {
	n, err := fd.PRead(ctx, dst, fd.off, opts)
	fd.offMu.Lock()
	fd.off += n
	fd.offMu.Unlock()
	return n, err
}

// PWrite implements vfs.FileDescriptionImpl.PWrite.
func (fd *regularFileFD) PWrite(ctx context.Context, src usermem.IOSequence, offset int64, opts vfs.WriteOptions) (int64, error) {
	// write(2) specifies that EBADF must be returned if the fd is not open for
	// writing.
	return 0, syserror.EBADF
}

// Write implements vfs.FileDescriptionImpl.Write.
func (fd *regularFileFD) Write(ctx context.Context, src usermem.IOSequence, opts vfs.WriteOptions) (int64, error) {
	n, err := fd.PWrite(ctx, src, fd.off, opts)
	fd.offMu.Lock()
	fd.off += n
	fd.offMu.Unlock()
	return n, err
}

// IterDirents implements vfs.FileDescriptionImpl.IterDirents.
func (fd *regularFileFD) IterDirents(ctx context.Context, cb vfs.IterDirentsCallback) error {
	return syserror.ENOTDIR
}

// Seek implements vfs.FileDescriptionImpl.Seek.
func (fd *regularFileFD) Seek(ctx context.Context, offset int64, whence int32) (int64, error) {
	fd.offMu.Lock()
	defer fd.offMu.Unlock()
	switch whence {
	case linux.SEEK_SET:
		// Use offset as specified.
	case linux.SEEK_CUR:
		offset += fd.off
	case linux.SEEK_END:
		offset += int64(fd.inode().diskInode.Size())
	default:
		return 0, syserror.EINVAL
	}
	if offset < 0 {
		return 0, syserror.EINVAL
	}
	fd.off = offset
	return offset, nil
}

// ConfigureMMap implements vfs.FileDescriptionImpl.ConfigureMMap.
func (fd *regularFileFD) ConfigureMMap(ctx context.Context, opts *memmap.MMapOpts) error {
	// TODO(b/134676337): Implement mmap(2).
	return syserror.ENODEV
}
