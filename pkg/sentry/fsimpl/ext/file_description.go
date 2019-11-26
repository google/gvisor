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
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/sentry/context"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/syserror"
)

// fileDescription is embedded by ext implementations of
// vfs.FileDescriptionImpl.
type fileDescription struct {
	vfsfd vfs.FileDescription
	vfs.FileDescriptionDefaultImpl

	// flags is the same as vfs.OpenOptions.Flags which are passed to
	// vfs.FilesystemImpl.OpenAt.
	// TODO(b/134676337): syscalls like read(2), write(2), fchmod(2), fchown(2),
	// fgetxattr(2), ioctl(2), mmap(2) should fail with EBADF if O_PATH is set.
	// Only close(2), fstat(2), fstatfs(2) should work.
	flags uint32
}

func (fd *fileDescription) filesystem() *filesystem {
	return fd.vfsfd.Mount().Filesystem().Impl().(*filesystem)
}

func (fd *fileDescription) inode() *inode {
	return fd.vfsfd.Dentry().Impl().(*dentry).inode
}

// StatusFlags implements vfs.FileDescriptionImpl.StatusFlags.
func (fd *fileDescription) StatusFlags(ctx context.Context) (uint32, error) {
	return fd.flags, nil
}

// SetStatusFlags implements vfs.FileDescriptionImpl.SetStatusFlags.
func (fd *fileDescription) SetStatusFlags(ctx context.Context, flags uint32) error {
	// None of the flags settable by fcntl(F_SETFL) are supported, so this is a
	// no-op.
	return nil
}

// Stat implements vfs.FileDescriptionImpl.Stat.
func (fd *fileDescription) Stat(ctx context.Context, opts vfs.StatOptions) (linux.Statx, error) {
	var stat linux.Statx
	fd.inode().statTo(&stat)
	return stat, nil
}

// SetStat implements vfs.FileDescriptionImpl.SetStat.
func (fd *fileDescription) SetStat(ctx context.Context, opts vfs.SetStatOptions) error {
	if opts.Stat.Mask == 0 {
		return nil
	}
	return syserror.EPERM
}

// SetStat implements vfs.FileDescriptionImpl.StatFS.
func (fd *fileDescription) StatFS(ctx context.Context) (linux.Statfs, error) {
	var stat linux.Statfs
	fd.filesystem().statTo(&stat)
	return stat, nil
}

// Sync implements vfs.FileDescriptionImpl.Sync.
func (fd *fileDescription) Sync(ctx context.Context) error {
	return nil
}
