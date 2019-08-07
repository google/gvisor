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

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/fd"
	"gvisor.dev/gvisor/pkg/log"
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

// getDeviceFd returns an io.ReaderAt to the underlying device.
// Currently there are two ways of mounting an ext(2/3/4) fs:
//   1. Specify a mount with our internal special MountType in the OCI spec.
//   2. Expose the device to the container and mount it from application layer.
func getDeviceFd(source string, opts vfs.NewFilesystemOptions) (io.ReaderAt, error) {
	if opts.InternalData == nil {
		// User mount call.
		// TODO(b/134676337): Open the device specified by `source` and return that.
		panic("unimplemented")
	}

	// NewFilesystem call originated from within the sentry.
	devFd, ok := opts.InternalData.(int)
	if !ok {
		return nil, errors.New("internal data for ext fs must be an int containing the file descriptor to device")
	}

	if devFd < 0 {
		return nil, fmt.Errorf("ext device file descriptor is not valid: %d", devFd)
	}

	// The fd.ReadWriter returned from fd.NewReadWriter() does not take ownership
	// of the file descriptor and hence will not close it when it is garbage
	// collected.
	return fd.NewReadWriter(devFd), nil
}

// isCompatible checks if the superblock has feature sets which are compatible.
// We only need to check the superblock incompatible feature set since we are
// mounting readonly. We will also need to check readonly compatible feature
// set when mounting for read/write.
func isCompatible(sb disklayout.SuperBlock) bool {
	// Please note that what is being checked is limited based on the fact that we
	// are mounting readonly and that we are not journaling. When mounting
	// read/write or with a journal, this must be reevaluated.
	incompatFeatures := sb.IncompatibleFeatures()
	if incompatFeatures.MetaBG {
		log.Warningf("ext fs: meta block groups are not supported")
		return false
	}
	if incompatFeatures.MMP {
		log.Warningf("ext fs: multiple mount protection is not supported")
		return false
	}
	if incompatFeatures.Encrypted {
		log.Warningf("ext fs: encrypted inodes not supported")
		return false
	}
	if incompatFeatures.InlineData {
		log.Warningf("ext fs: inline files not supported")
		return false
	}
	return true
}

// NewFilesystem implements vfs.FilesystemType.NewFilesystem.
func (fstype filesystemType) NewFilesystem(ctx context.Context, creds *auth.Credentials, source string, opts vfs.NewFilesystemOptions) (*vfs.Filesystem, *vfs.Dentry, error) {
	// TODO(b/134676337): Ensure that the user is mounting readonly. If not,
	// EACCESS should be returned according to mount(2). Filesystem independent
	// flags (like readonly) are currently not available in pkg/sentry/vfs.

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

	// Refuse to mount if the filesystem is incompatible.
	if !isCompatible(fs.sb) {
		return nil, nil, syserror.EINVAL
	}

	fs.bgs, err = readBlockGroups(dev, fs.sb)
	if err != nil {
		return nil, nil, err
	}

	rootInode, err := fs.getOrCreateInodeLocked(disklayout.RootDirInode)
	if err != nil {
		return nil, nil, err
	}
	rootInode.incRef()

	return &fs.vfsfs, &newDentry(rootInode).vfsd, nil
}
