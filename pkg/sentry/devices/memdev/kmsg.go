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
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/syserror"
	"gvisor.dev/gvisor/pkg/usermem"
	"gvisor.dev/gvisor/pkg/waiter"
)

const kmsgDevMinor = 11

// kmsgDevice implements vfs.Device for /dev/kmsg.
type kmsgDevice struct{}

// Open implements vfs.Device.Open.
func (kmsgDevice) Open(ctx context.Context, mnt *vfs.Mount, vfsd *vfs.Dentry, opts vfs.OpenOptions) (*vfs.FileDescription, error) {
	creds := auth.CredentialsFromContext(ctx)
	k := kernel.KernelFromContext(ctx)
	if opts.Flags&linux.O_ACCMODE != linux.O_RDONLY &&
		!creds.HasCapabilityIn(linux.CAP_SYSLOG, k.RootUserNamespace()) &&
		!creds.HasCapabilityIn(linux.CAP_SYS_ADMIN, k.RootUserNamespace()) {
		return nil, syserror.EPERM
	}
	fd := &kmsgFD{
		kernel:   k,
		index:    k.Syslog().FirstIndex(),
		sequence: k.Syslog().FirstSequence(),
	}
	if err := fd.vfsfd.Init(fd, opts.Flags, mnt, vfsd, &vfs.FileDescriptionOptions{
		UseDentryMetadata: true,
	}); err != nil {
		return nil, err
	}
	return &fd.vfsfd, nil
}

// kmsgFD implements vfs.FileDescriptionImpl for /dev/kmsg.
type kmsgFD struct {
	vfsfd vfs.FileDescription
	vfs.FileDescriptionDefaultImpl
	vfs.DentryMetadataFileDescriptionImpl
	vfs.NoLockFD

	kernel *kernel.Kernel

	// sequence is sequence number of syslog record for current kmsg fd.
	sequence uint64
	// index is index of syslog record for current kmsg fd.
	index uint32
}

// Release implements vfs.FileDescriptionImpl.Release.
func (fd *kmsgFD) Release() {}

// Read implements vfs.FileDescriptionImpl.Read.
func (fd *kmsgFD) Read(ctx context.Context, dst usermem.IOSequence, opts vfs.ReadOptions) (int64, error) {
	seq, idx, bytesCopied, err := fd.kernel.Syslog().DevKmsgRead(ctx, fd.sequence, fd.index, dst, fd.vfsfd.StatusFlags())
	fd.sequence = seq
	fd.index = idx
	if err != nil {
		return 0, err
	}
	return bytesCopied, nil
}

// Write implements vfs.FileDescriptionImpl.Write.
func (fd *kmsgFD) Write(ctx context.Context, src usermem.IOSequence, opts vfs.WriteOptions) (int64, error) {
	return fd.kernel.Syslog().DevKmsgWrite(ctx, src)
}

// Seek implements vfs.FileDescriptionImpl.Seek.
func (fd *kmsgFD) Seek(ctx context.Context, offset int64, whence int32) (int64, error) {
	if offset != 0 {
		return 0, syserror.ESPIPE
	}
	seq, idx, err := fd.kernel.Syslog().DevKmsgSeek(ctx, whence)
	if err != nil {
		return 0, err
	}
	fd.sequence = seq
	fd.index = idx
	return 0, nil
}

// Readiness implements waiter.Waitable.Readiness.
func (fd *kmsgFD) Readiness(mask waiter.EventMask) waiter.EventMask {
	return fd.kernel.Syslog().DevKmsgReadiness(fd.sequence, mask)
}
