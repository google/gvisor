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

	"gvisor.dev/gvisor/pkg/sentry/context"
	"gvisor.dev/gvisor/pkg/sentry/fs/ext/disklayout"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/syserror"
)

// filesystem implements vfs.FilesystemImpl.
type filesystem struct {
	// TODO(b/134676337): Remove when all methods have been implemented.
	vfs.FilesystemImpl

	vfsfs vfs.Filesystem

	// mu serializes changes to the Dentry tree and the usage of the read seeker.
	mu sync.Mutex

	// dev is the ReadSeeker for the underlying fs device. It is protected by mu.
	//
	// The ext filesystems aim to maximize locality, i.e. place all the data
	// blocks of a file close together. On a spinning disk, locality reduces the
	// amount of movement of the head hence speeding up IO operations. On an SSD
	// there are no moving parts but locality increases the size of each transer
	// request. Hence, having mutual exclusion on the read seeker while reading a
	// file *should* help in achieving the intended performance gains.
	//
	// Note: This synchronization was not coupled with the ReadSeeker itself
	// because we want to synchronize across read/seek operations for the
	// performance gains mentioned above. Helps enforcing one-file-at-a-time IO.
	dev io.ReadSeeker

	// inodeCache maps absolute inode numbers to the corresponding Inode struct.
	// Inodes should be removed from this once their reference count hits 0.
	//
	// Protected by mu because every addition and removal from this corresponds to
	// a change in the dentry tree.
	inodeCache map[uint32]*inode

	// sb represents the filesystem superblock. Immutable after initialization.
	sb disklayout.SuperBlock

	// bgs represents all the block group descriptors for the filesystem.
	// Immutable after initialization.
	bgs []disklayout.BlockGroup
}

// Compiles only if filesystem implements vfs.FilesystemImpl.
var _ vfs.FilesystemImpl = (*filesystem)(nil)

// getOrCreateInode gets the inode corresponding to the inode number passed in.
// It creates a new one with the given inode number if one does not exist.
//
// Preconditions: must be holding fs.mu.
func (fs *filesystem) getOrCreateInode(inodeNum uint32) (*inode, error) {
	if in, ok := fs.inodeCache[inodeNum]; ok {
		return in, nil
	}

	in, err := newInode(fs.dev, fs.sb, fs.bgs, inodeNum)
	if err != nil {
		return nil, err
	}

	fs.inodeCache[inodeNum] = in
	return in, nil
}

// Release implements vfs.FilesystemImpl.Release.
func (fs *filesystem) Release() {
}

// Sync implements vfs.FilesystemImpl.Sync.
func (fs *filesystem) Sync(ctx context.Context) error {
	// This is a readonly filesystem for now.
	return nil
}

// The vfs.FilesystemImpl functions below return EROFS because their respective
// man pages say that EROFS must be returned if the path resolves to a file on
// a read-only filesystem.

// TODO(b/134676337): Implement path traversal and return EROFS only if the
// path resolves to a Dentry within ext fs.

// MkdirAt implements vfs.FilesystemImpl.MkdirAt.
func (fs *filesystem) MkdirAt(ctx context.Context, rp *vfs.ResolvingPath, opts vfs.MkdirOptions) error {
	return syserror.EROFS
}

// MknodAt implements vfs.FilesystemImpl.MknodAt.
func (fs *filesystem) MknodAt(ctx context.Context, rp *vfs.ResolvingPath, opts vfs.MknodOptions) error {
	return syserror.EROFS
}

// RenameAt implements vfs.FilesystemImpl.RenameAt.
func (fs *filesystem) RenameAt(ctx context.Context, rp *vfs.ResolvingPath, vd vfs.VirtualDentry, opts vfs.RenameOptions) error {
	return syserror.EROFS
}

// RmdirAt implements vfs.FilesystemImpl.RmdirAt.
func (fs *filesystem) RmdirAt(ctx context.Context, rp *vfs.ResolvingPath) error {
	return syserror.EROFS
}

// SetStatAt implements vfs.FilesystemImpl.SetStatAt.
func (fs *filesystem) SetStatAt(ctx context.Context, rp *vfs.ResolvingPath, opts vfs.SetStatOptions) error {
	return syserror.EROFS
}

// SymlinkAt implements vfs.FilesystemImpl.SymlinkAt.
func (fs *filesystem) SymlinkAt(ctx context.Context, rp *vfs.ResolvingPath, target string) error {
	return syserror.EROFS
}

// UnlinkAt implements vfs.FilesystemImpl.UnlinkAt.
func (fs *filesystem) UnlinkAt(ctx context.Context, rp *vfs.ResolvingPath) error {
	return syserror.EROFS
}
