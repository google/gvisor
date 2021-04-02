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
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/tmpfs"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/usermem"
)

const zeroDevMinor = 5

// zeroDevice implements vfs.Device for /dev/zero.
//
// +stateify savable
type zeroDevice struct{}

// Open implements vfs.Device.Open.
func (zeroDevice) Open(ctx context.Context, mnt *vfs.Mount, vfsd *vfs.Dentry, opts vfs.OpenOptions) (*vfs.FileDescription, error) {
	fd := &zeroFD{}
	if err := fd.vfsfd.Init(fd, opts.Flags, mnt, vfsd, &vfs.FileDescriptionOptions{
		UseDentryMetadata: true,
	}); err != nil {
		return nil, err
	}
	return &fd.vfsfd, nil
}

// zeroFD implements vfs.FileDescriptionImpl for /dev/zero.
//
// +stateify savable
type zeroFD struct {
	vfsfd vfs.FileDescription
	vfs.FileDescriptionDefaultImpl
	vfs.DentryMetadataFileDescriptionImpl
	vfs.NoLockFD
}

// Release implements vfs.FileDescriptionImpl.Release.
func (fd *zeroFD) Release(context.Context) {
	// noop
}

// PRead implements vfs.FileDescriptionImpl.PRead.
func (fd *zeroFD) PRead(ctx context.Context, dst usermem.IOSequence, offset int64, opts vfs.ReadOptions) (int64, error) {
	return dst.ZeroOut(ctx, dst.NumBytes())
}

// Read implements vfs.FileDescriptionImpl.Read.
func (fd *zeroFD) Read(ctx context.Context, dst usermem.IOSequence, opts vfs.ReadOptions) (int64, error) {
	return dst.ZeroOut(ctx, dst.NumBytes())
}

// PWrite implements vfs.FileDescriptionImpl.PWrite.
func (fd *zeroFD) PWrite(ctx context.Context, src usermem.IOSequence, offset int64, opts vfs.WriteOptions) (int64, error) {
	return src.NumBytes(), nil
}

// Write implements vfs.FileDescriptionImpl.Write.
func (fd *zeroFD) Write(ctx context.Context, src usermem.IOSequence, opts vfs.WriteOptions) (int64, error) {
	return src.NumBytes(), nil
}

// Seek implements vfs.FileDescriptionImpl.Seek.
func (fd *zeroFD) Seek(ctx context.Context, offset int64, whence int32) (int64, error) {
	return 0, nil
}

// ConfigureMMap implements vfs.FileDescriptionImpl.ConfigureMMap.
func (fd *zeroFD) ConfigureMMap(ctx context.Context, opts *memmap.MMapOpts) error {
	if opts.Private || !opts.MaxPerms.Write {
		// This mapping will never permit writing to the "underlying file" (in
		// Linux terms, it isn't VM_SHARED), so implement it as an anonymous
		// mapping, but back it with fd; this is what Linux does, and is
		// actually application-visible because the resulting VMA will show up
		// in /proc/[pid]/maps with fd.vfsfd.VirtualDentry()'s path rather than
		// "/dev/zero (deleted)".
		opts.Offset = 0
		opts.MappingIdentity = &fd.vfsfd
		opts.SentryOwnedContent = true
		opts.MappingIdentity.IncRef()
		return nil
	}
	tmpfsFD, err := tmpfs.NewZeroFile(ctx, auth.CredentialsFromContext(ctx), kernel.KernelFromContext(ctx).ShmMount(), opts.Length)
	if err != nil {
		return err
	}
	defer tmpfsFD.DecRef(ctx)
	return tmpfsFD.ConfigureMMap(ctx, opts)
}
