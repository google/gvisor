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
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/kernfs"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/pgalloc"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/syserror"
	"gvisor.dev/gvisor/pkg/usermem"
)

func (fs *filesystem) newKcovFile(ctx context.Context, creds *auth.Credentials) *kernfs.Dentry {
	mfp := pgalloc.MemoryFileProviderFromContext(ctx)
	if mfp == nil {
		panic("MemoryFileProviderFromContext returned nil")
	}
	k := &kcovInode{mfp: mfp}
	k.InodeAttrs.Init(creds, 0, 0, fs.NextIno(), linux.S_IFREG|0666) // TODO(deandeng): device numbers; mode should be 0600 (changed for testing)
	d := &kernfs.Dentry{}
	d.Init(k)
	return d
}

// kcovInode implements kernfs.Inode.
type kcovInode struct {
	kernfs.InodeAttrs
	kernfs.InodeNoopRefCount
	kernfs.InodeNotSymlink
	kernfs.InodeNotDirectory

	mfp pgalloc.MemoryFileProvider
}

func (i *kcovInode) Open(ctx context.Context, rp *vfs.ResolvingPath, vfsd *vfs.Dentry, opts vfs.OpenOptions) (*vfs.FileDescription, error) {
  fd := &kcovFD{
    inode: i,
    kcov: kernel.NewKcov(i.mfp),
  }

	if err := fd.vfsfd.Init(fd, opts.Flags, rp.Mount(), vfsd, &vfs.FileDescriptionOptions{
		DenyPRead:  true,
		DenyPWrite: true,
	}); err != nil {
		return nil, err
	}
	return &fd.vfsfd, nil
}

type kcovFD struct {
	vfs.FileDescriptionDefaultImpl
	vfs.NoLockFD

	vfsfd vfs.FileDescription
  inode *kcovInode
  kcov *kernel.Kcov
}

// Ioctl implements vfs.FileDescriptionImpl.Ioctl.
func (fd *kcovFD) Ioctl(ctx context.Context, uio usermem.IO, args arch.SyscallArguments) (uintptr, error) {
	switch uint32(args[1].Int()) {
	case linux.KCOV_INIT_TRACE:
		return 0, fd.kcov.InitTrace(args[2].Uint64())
	case linux.KCOV_ENABLE:
		return 0, fd.kcov.EnableTrace(ctx, uint8(args[2].Uint64()))
	case linux.KCOV_DISABLE:
		if args[2].Int() != 0 {
			// This arg is unused; it should be 0.
			return 0, syserror.EINVAL
		}
		return 0, fd.kcov.DisableTrace(ctx)
	default:
		return 0, syserror.ENOTTY
	}
}

// ConfigureMmap implements vfs.FileDescriptionImpl.ConfigureMmap.
func (fd *kcovFD) ConfigureMMap(ctx context.Context, opts *memmap.MMapOpts) error {
	return fd.kcov.ConfigureMMap(ctx, opts)
}

// Release implements vfs.FileDescriptionImpl.Release.
func (fd *kcovFD) Release() {
  // TODO(deandeng): There's some ref counting stuff going on in the kernel.
  // This seems sufficient..?
  fd.kcov.Reset()
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
