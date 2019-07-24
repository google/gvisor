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

// Package ext implements readonly ext(2/3/4) filesystems.
package ext

import (
	"errors"
	"fmt"
	"io"
	"os"
	"sync"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/sentry/context"
	"gvisor.dev/gvisor/pkg/sentry/fs/ext/disklayout"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/syserror"
)

// filesystemType implements vfs.FilesystemType.
type filesystemType struct{}

// Compiles only if filesystemType implements vfs.FilesystemType.
var _ vfs.FilesystemType = (*filesystemType)(nil)

// filesystem implements vfs.FilesystemImpl.
type filesystem struct {
	// TODO(b/134676337): Remove when all methods have been implemented.
	vfs.FilesystemImpl

	vfsfs vfs.Filesystem

	// mu serializes changes to the dentry tree and the usage of the read seeker.
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

// getDeviceFd returns the read seeker to the underlying device.
// Currently there are two ways of mounting an ext(2/3/4) fs:
//   1. Specify a mount with our internal special MountType in the OCI spec.
//   2. Expose the device to the container and mount it from application layer.
func getDeviceFd(source string, opts vfs.NewFilesystemOptions) (io.ReadSeeker, error) {
	if opts.InternalData == nil {
		// User mount call.
		// TODO(b/134676337): Open the device specified by `source` and return that.
		panic("unimplemented")
	}

	// NewFilesystem call originated from within the sentry.
	fd, ok := opts.InternalData.(uintptr)
	if !ok {
		return nil, errors.New("internal data for ext fs must be a uintptr containing the file descriptor to device")
	}

	// We do not close this file because that would close the underlying device
	// file descriptor (which is required for reading the fs from disk).
	// TODO(b/134676337): Use pkg/fd instead.
	deviceFile := os.NewFile(fd, source)
	if deviceFile == nil {
		return nil, fmt.Errorf("ext4 device file descriptor is not valid: %d", fd)
	}

	return deviceFile, nil
}

// NewFilesystem implements vfs.FilesystemType.NewFilesystem.
func (fstype filesystemType) NewFilesystem(ctx context.Context, creds *auth.Credentials, source string, opts vfs.NewFilesystemOptions) (*vfs.Filesystem, *vfs.Dentry, error) {
	dev, err := getDeviceFd(source, opts)
	if err != nil {
		return nil, nil, err
	}

	fs := filesystem{dev: dev, inodeCache: make(map[uint32]*inode)}
	fs.vfsfs.Init(&fs)
	fs.sb, err = readSuperBlock(dev)
	if err != nil {
		return nil, nil, err
	}

	if fs.sb.Magic() != linux.EXT_SUPER_MAGIC {
		// mount(2) specifies that EINVAL should be returned if the superblock is
		// invalid.
		return nil, nil, syserror.EINVAL
	}

	fs.bgs, err = readBlockGroups(dev, fs.sb)
	if err != nil {
		return nil, nil, err
	}

	return &fs.vfsfs, nil, nil
}

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
