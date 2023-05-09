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

// ListXattr implements FileDescriptionImpl.ListXattr.
func (fd *opathFD) ListXattr(ctx context.Context, size uint64) ([]string, error) {
	return nil, linuxerr.EBADF
}

// GetXattr implements FileDescriptionImpl.GetXattr.
func (fd *opathFD) GetXattr(ctx context.Context, opts GetXattrOptions) (string, error) {
	return "", linuxerr.EBADF
}

// SetXattr implements FileDescriptionImpl.SetXattr.
func (fd *opathFD) SetXattr(ctx context.Context, opts SetXattrOptions) error {
	return linuxerr.EBADF
}

// RemoveXattr implements FileDescriptionImpl.RemoveXattr.
func (fd *opathFD) RemoveXattr(ctx context.Context, name string) error {
	return linuxerr.EBADF
}

// Sync implements FileDescriptionImpl.Sync.
func (fd *opathFD) Sync(ctx context.Context) error {
	return linuxerr.EBADF
}

// SetStat implements FileDescriptionImpl.SetStat.
func (fd *opathFD) SetStat(ctx context.Context, opts SetStatOptions) error {
	return linuxerr.EBADF
}

// Stat implements FileDescriptionImpl.Stat.
func (fd *opathFD) Stat(ctx context.Context, opts StatOptions) (linux.Statx, error) {
	vfsObj := fd.vfsfd.vd.mount.vfs
	rp := vfsObj.getResolvingPath(auth.CredentialsFromContext(ctx), &PathOperation{
		Root:  fd.vfsfd.vd,
		Start: fd.vfsfd.vd,
	})
	stat, err := fd.vfsfd.vd.mount.fs.impl.StatAt(ctx, rp, opts)
	rp.Release(ctx)
	return stat, err
}

// StatFS returns metadata for the filesystem containing the file represented
// by fd.
func (fd *opathFD) StatFS(ctx context.Context) (linux.Statfs, error) {
	vfsObj := fd.vfsfd.vd.mount.vfs
	rp := vfsObj.getResolvingPath(auth.CredentialsFromContext(ctx), &PathOperation{
		Root:  fd.vfsfd.vd,
		Start: fd.vfsfd.vd,
	})
	statfs, err := fd.vfsfd.vd.mount.fs.impl.StatFSAt(ctx, rp)
	rp.Release(ctx)
	return statfs, err
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
	if err := fd.vfsfd.Init(fd, flags, vd.Mount(), vd.Dentry(), &FileDescriptionOptions{}); err != nil {
		return nil, err
	}
	return &fd.vfsfd, err
}
