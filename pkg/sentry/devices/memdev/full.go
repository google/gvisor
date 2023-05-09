// Copyright 2020 The gVisor Authors.
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

package memdev

import (
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/usermem"
)

const fullDevMinor = 7

// fullDevice implements vfs.Device for /dev/full.
//
// +stateify savable
type fullDevice struct{}

// Open implements vfs.Device.Open.
func (fullDevice) Open(ctx context.Context, mnt *vfs.Mount, vfsd *vfs.Dentry, opts vfs.OpenOptions) (*vfs.FileDescription, error) {
	fd := &fullFD{}
	if err := fd.vfsfd.Init(fd, opts.Flags, mnt, vfsd, &vfs.FileDescriptionOptions{
		UseDentryMetadata: true,
	}); err != nil {
		return nil, err
	}
	return &fd.vfsfd, nil
}

// fullFD implements vfs.FileDescriptionImpl for /dev/full.
//
// +stateify savable
type fullFD struct {
	vfsfd vfs.FileDescription
	vfs.FileDescriptionDefaultImpl
	vfs.DentryMetadataFileDescriptionImpl
	vfs.NoLockFD
}

// Release implements vfs.FileDescriptionImpl.Release.
func (fd *fullFD) Release(context.Context) {
	// noop
}

// PRead implements vfs.FileDescriptionImpl.PRead.
func (fd *fullFD) PRead(ctx context.Context, dst usermem.IOSequence, offset int64, opts vfs.ReadOptions) (int64, error) {
	return dst.ZeroOut(ctx, dst.NumBytes())
}

// Read implements vfs.FileDescriptionImpl.Read.
func (fd *fullFD) Read(ctx context.Context, dst usermem.IOSequence, opts vfs.ReadOptions) (int64, error) {
	return dst.ZeroOut(ctx, dst.NumBytes())
}

// PWrite implements vfs.FileDescriptionImpl.PWrite.
func (fd *fullFD) PWrite(ctx context.Context, src usermem.IOSequence, offset int64, opts vfs.WriteOptions) (int64, error) {
	return 0, linuxerr.ENOSPC
}

// Write implements vfs.FileDescriptionImpl.Write.
func (fd *fullFD) Write(ctx context.Context, src usermem.IOSequence, opts vfs.WriteOptions) (int64, error) {
	return 0, linuxerr.ENOSPC
}

// Seek implements vfs.FileDescriptionImpl.Seek.
func (fd *fullFD) Seek(ctx context.Context, offset int64, whence int32) (int64, error) {
	return 0, nil
}
