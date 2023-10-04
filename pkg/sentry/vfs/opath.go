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

package vfs

import (
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/usermem"
)

// opathFD implements FileDescriptionImpl for a file description opened with O_PATH.
//
// +stateify savable
type opathFD struct {
	vfsfd FileDescription
	FileDescriptionDefaultImpl
	DentryMetadataFileDescriptionImpl
	BadLockFD
}

// Release implements FileDescriptionImpl.Release.
func (fd *opathFD) Release(context.Context) {
	// noop
}

// Allocate implements FileDescriptionImpl.Allocate.
func (fd *opathFD) Allocate(ctx context.Context, mode, offset, length uint64) error {
	return linuxerr.EBADF
}

// PRead implements FileDescriptionImpl.PRead.
func (fd *opathFD) PRead(ctx context.Context, dst usermem.IOSequence, offset int64, opts ReadOptions) (int64, error) {
	return 0, linuxerr.EBADF
}

// Read implements FileDescriptionImpl.Read.
func (fd *opathFD) Read(ctx context.Context, dst usermem.IOSequence, opts ReadOptions) (int64, error) {
	return 0, linuxerr.EBADF
}

// PWrite implements FileDescriptionImpl.PWrite.
func (fd *opathFD) PWrite(ctx context.Context, src usermem.IOSequence, offset int64, opts WriteOptions) (int64, error) {
	return 0, linuxerr.EBADF
}

// Write implements FileDescriptionImpl.Write.
func (fd *opathFD) Write(ctx context.Context, src usermem.IOSequence, opts WriteOptions) (int64, error) {
	return 0, linuxerr.EBADF
}

// Ioctl implements FileDescriptionImpl.Ioctl.
func (fd *opathFD) Ioctl(ctx context.Context, uio usermem.IO, sysno uintptr, args arch.SyscallArguments) (uintptr, error) {
	return 0, linuxerr.EBADF
}

// IterDirents implements FileDescriptionImpl.IterDirents.
func (fd *opathFD) IterDirents(ctx context.Context, cb IterDirentsCallback) error {
	return linuxerr.EBADF
}

// Seek implements FileDescriptionImpl.Seek.
func (fd *opathFD) Seek(ctx context.Context, offset int64, whence int32) (int64, error) {
	return 0, linuxerr.EBADF
}

// ConfigureMMap implements FileDescriptionImpl.ConfigureMMap.
func (fd *opathFD) ConfigureMMap(ctx context.Context, opts *memmap.MMapOpts) error {
	return linuxerr.EBADF
}

// Sync implements FileDescriptionImpl.Sync.
func (fd *opathFD) Sync(ctx context.Context) error {
	return linuxerr.EBADF
}

func (vfs *VirtualFilesystem) openOPathFD(ctx context.Context, creds *auth.Credentials, pop *PathOperation, flags uint32) (*FileDescription, error) {
	vd, err := vfs.GetDentryAt(ctx, creds, pop, &GetDentryOptions{})
	if err != nil {
		return nil, err
	}
	defer vd.DecRef(ctx)

	if flags&linux.O_DIRECTORY != 0 {
		stat, err := vfs.StatAt(ctx, creds, &PathOperation{
			Root:  vd,
			Start: vd,
		}, &StatOptions{
			Mask: linux.STATX_MODE,
		})
		if err != nil {
			return nil, err
		}
		if stat.Mode&linux.S_IFDIR == 0 {
			return nil, linuxerr.ENOTDIR
		}
	}

	fd := &opathFD{}
	if err := fd.vfsfd.Init(fd, flags, vd.Mount(), vd.Dentry(), &FileDescriptionOptions{
		// Pass along Stat, SetStat, StatFS and Xattr calls to fsimpl.
		UseDentryMetadata: true,
	}); err != nil {
		return nil, err
	}
	return &fd.vfsfd, err
}
