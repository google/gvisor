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

package sys

import (
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/kernfs"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/usermem"
)

func (fs *filesystem) newKcovFile(ctx context.Context, creds *auth.Credentials) kernfs.Inode {
	k := &kcovInode{}
	k.InodeAttrs.Init(ctx, creds, 0, 0, fs.NextIno(), linux.S_IFREG|0600)
	return k
}

// kcovInode implements kernfs.Inode.
//
// +stateify savable
type kcovInode struct {
	kernfs.InodeAttrs
	kernfs.InodeNoopRefCount
	kernfs.InodeNotDirectory
	kernfs.InodeNotSymlink
	implStatFS
}

func (i *kcovInode) Open(ctx context.Context, rp *vfs.ResolvingPath, d *kernfs.Dentry, opts vfs.OpenOptions) (*vfs.FileDescription, error) {
	k := kernel.KernelFromContext(ctx)
	if k == nil {
		panic("KernelFromContext returned nil")
	}
	fd := &kcovFD{
		inode: i,
		kcov:  k.NewKcov(),
	}

	if err := fd.vfsfd.Init(fd, opts.Flags, rp.Mount(), d.VFSDentry(), &vfs.FileDescriptionOptions{
		DenyPRead:  true,
		DenyPWrite: true,
	}); err != nil {
		return nil, err
	}
	return &fd.vfsfd, nil
}

// +stateify savable
type kcovFD struct {
	vfs.FileDescriptionDefaultImpl
	vfs.NoLockFD

	vfsfd vfs.FileDescription
	inode *kcovInode
	kcov  *kernel.Kcov
}

// Ioctl implements vfs.FileDescriptionImpl.Ioctl.
func (fd *kcovFD) Ioctl(ctx context.Context, uio usermem.IO, args arch.SyscallArguments) (uintptr, error) {
	cmd := uint32(args[1].Int())
	arg := args[2].Uint64()
	switch uint32(cmd) {
	case linux.KCOV_INIT_TRACE:
		return 0, fd.kcov.InitTrace(arg)
	case linux.KCOV_ENABLE:
		return 0, fd.kcov.EnableTrace(ctx, uint8(arg))
	case linux.KCOV_DISABLE:
		if arg != 0 {
			// This arg is unused; it should be 0.
			return 0, linuxerr.EINVAL
		}
		return 0, fd.kcov.DisableTrace(ctx)
	default:
		return 0, linuxerr.ENOTTY
	}
}

// ConfigureMmap implements vfs.FileDescriptionImpl.ConfigureMmap.
func (fd *kcovFD) ConfigureMMap(ctx context.Context, opts *memmap.MMapOpts) error {
	return fd.kcov.ConfigureMMap(ctx, opts)
}

// Release implements vfs.FileDescriptionImpl.Release.
func (fd *kcovFD) Release(ctx context.Context) {
	// kcov instances have reference counts in Linux, but this seems sufficient
	// for our purposes.
	fd.kcov.Clear(ctx)
}

// SetStat implements vfs.FileDescriptionImpl.SetStat.
func (fd *kcovFD) SetStat(ctx context.Context, opts vfs.SetStatOptions) error {
	creds := auth.CredentialsFromContext(ctx)
	fs := fd.vfsfd.VirtualDentry().Mount().Filesystem()
	return fd.inode.SetStat(ctx, fs, creds, opts)
}

// Stat implements vfs.FileDescriptionImpl.Stat.
func (fd *kcovFD) Stat(ctx context.Context, opts vfs.StatOptions) (linux.Statx, error) {
	return fd.inode.Stat(ctx, fd.vfsfd.Mount().Filesystem(), opts)
}
