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

package gofer

import (
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/syserror"
	"gvisor.dev/gvisor/pkg/usermem"
)

func (d *dentry) isSymlink() bool {
	return d.fileType() == linux.S_IFLNK
}

// Precondition: d.isSymlink().
func (d *dentry) readlink(ctx context.Context, mnt *vfs.Mount) (string, error) {
	if d.fs.opts.interop != InteropModeShared {
		d.touchAtime(mnt)
		d.dataMu.Lock()
		if d.haveTarget {
			target := d.target
			d.dataMu.Unlock()
			return target, nil
		}
	}
	target, err := d.file.readlink(ctx)
	if d.fs.opts.interop != InteropModeShared {
		if err == nil {
			d.haveTarget = true
			d.target = target
		}
		d.dataMu.Unlock()
	}
	return target, err
}

// +stateify savable
type symlinkFD struct {
	fileDescription
}

// Release implements vfs.FileDescriptionImpl.Release.
func (fd *symlinkFD) Release(context.Context) {
	// noop
}

// Allocate implements vfs.FileDescriptionImpl.Allocate.
func (fd *symlinkFD) Allocate(ctx context.Context, mode, offset, length uint64) error {
	return syserror.ENODEV
}

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

// pwrite returns the number of bytes written, final offset and error. The
// final offset should be ignored by PWrite.
func (fd *symlinkFD) pwrite(ctx context.Context, src usermem.IOSequence, offset int64, opts vfs.WriteOptions) (written, finalOff int64, err error) {
	return 0, 0, syserror.EBADF
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

// ConfigureMMap implements vfs.FileDescriptionImpl.ConfigureMMap.
func (fd *symlinkFD) ConfigureMMap(ctx context.Context, opts *memmap.MMapOpts) error {
	return syserror.EBADF
}
