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
	"gvisor.dev/gvisor/pkg/sentry/context"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/usermem"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/syserror"
)

// symlink represents a symlink inode.
type symlink struct {
	inode  inode
	target string // immutable
}

// newSymlink is the symlink constructor. It reads out the symlink target from
// the inode (however it might have been stored).
func newSymlink(inode inode) (*symlink, error) {
	var file *symlink
	var link []byte

	// If the symlink target is lesser than 60 bytes, its stores in inode.Data().
	// Otherwise either extents or block maps will be used to store the link.
	size := inode.diskInode.Size()
	if size < 60 {
		link = inode.diskInode.Data()[:size]
	} else {
		// Create a regular file out of this inode and read out the target.
		regFile, err := newRegularFile(inode)
		if err != nil {
			return nil, err
		}

		link = make([]byte, size)
		if n, err := regFile.impl.ReadAt(link, 0); uint64(n) < size {
			return nil, err
		}
	}

	file = &symlink{inode: inode, target: string(link)}
	file.inode.impl = file
	return file, nil
}

func (in *inode) isSymlink() bool {
	_, ok := in.impl.(*symlink)
	return ok
}

// symlinkFD represents a symlink file description and implements implements
// vfs.FileDescriptionImpl. which may only be used if open options contains
// O_PATH. For this reason most of the functions return EBADF.
type symlinkFD struct {
	fileDescription
}

// Compiles only if symlinkFD implements vfs.FileDescriptionImpl.
var _ vfs.FileDescriptionImpl = (*symlinkFD)(nil)

// Release implements vfs.FileDescriptionImpl.Release.
func (fd *symlinkFD) Release() {}

// PRead implements vfs.FileDescriptionImpl.PRead.
func (fd *symlinkFD) PRead(ctx context.Context, dst usermem.IOSequence, offset int64, opts vfs.ReadOptions) (int64, error) {
	return 0, syserror.EBADF
}

// Read implements vfs.FileDescriptionImpl.Read.
func (fd *symlinkFD) Read(ctx context.Context, dst usermem.IOSequence, opts vfs.ReadOptions) (int64, error) {
	return 0, syserror.EBADF
}

// PWrite implements vfs.FileDescriptionImpl.PWrite.
func (fd *symlinkFD) PWrite(ctx context.Context, src usermem.IOSequence, offset int64, opts vfs.WriteOptions) (int64, error) {
	return 0, syserror.EBADF
}

// Write implements vfs.FileDescriptionImpl.Write.
func (fd *symlinkFD) Write(ctx context.Context, src usermem.IOSequence, opts vfs.WriteOptions) (int64, error) {
	return 0, syserror.EBADF
}

// IterDirents implements vfs.FileDescriptionImpl.IterDirents.
func (fd *symlinkFD) IterDirents(ctx context.Context, cb vfs.IterDirentsCallback) error {
	return syserror.ENOTDIR
}

// Seek implements vfs.FileDescriptionImpl.Seek.
func (fd *symlinkFD) Seek(ctx context.Context, offset int64, whence int32) (int64, error) {
	return 0, syserror.EBADF
}

// IterDirents implements vfs.FileDescriptionImpl.IterDirents.
func (fd *symlinkFD) ConfigureMMap(ctx context.Context, opts memmap.MMapOpts) error {
	return syserror.EBADF
}
