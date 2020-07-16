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

package devpts

import (
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	fslock "gvisor.dev/gvisor/pkg/sentry/fs/lock"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/kernfs"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/unimpl"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/syserror"
	"gvisor.dev/gvisor/pkg/usermem"
	"gvisor.dev/gvisor/pkg/waiter"
)

// masterInode is the inode for the master end of the Terminal.
type masterInode struct {
	kernfs.InodeAttrs
	kernfs.InodeNoopRefCount
	kernfs.InodeNotDirectory
	kernfs.InodeNotSymlink

	locks vfs.FileLocks

	// Keep a reference to this inode's dentry.
	dentry kernfs.Dentry

	// root is the devpts root inode.
	root *rootInode
}

var _ kernfs.Inode = (*masterInode)(nil)

// Open implements kernfs.Inode.Open.
func (mi *masterInode) Open(ctx context.Context, rp *vfs.ResolvingPath, vfsd *vfs.Dentry, opts vfs.OpenOptions) (*vfs.FileDescription, error) {
	t, err := mi.root.allocateTerminal(rp.Credentials())
	if err != nil {
		return nil, err
	}

	mi.IncRef()
	fd := &masterFileDescription{
		inode: mi,
		t:     t,
	}
	fd.LockFD.Init(&mi.locks)
	if err := fd.vfsfd.Init(fd, opts.Flags, rp.Mount(), vfsd, &vfs.FileDescriptionOptions{}); err != nil {
		mi.DecRef()
		return nil, err
	}
	return &fd.vfsfd, nil
}

// Stat implements kernfs.Inode.Stat.
func (mi *masterInode) Stat(ctx context.Context, vfsfs *vfs.Filesystem, opts vfs.StatOptions) (linux.Statx, error) {
	statx, err := mi.InodeAttrs.Stat(ctx, vfsfs, opts)
	if err != nil {
		return linux.Statx{}, err
	}
	statx.Blksize = 1024
	statx.RdevMajor = linux.TTYAUX_MAJOR
	statx.RdevMinor = linux.PTMX_MINOR
	return statx, nil
}

// SetStat implements kernfs.Inode.SetStat
func (mi *masterInode) SetStat(ctx context.Context, vfsfs *vfs.Filesystem, creds *auth.Credentials, opts vfs.SetStatOptions) error {
	if opts.Stat.Mask&linux.STATX_SIZE != 0 {
		return syserror.EINVAL
	}
	return mi.InodeAttrs.SetStat(ctx, vfsfs, creds, opts)
}

type masterFileDescription struct {
	vfsfd vfs.FileDescription
	vfs.FileDescriptionDefaultImpl
	vfs.LockFD

	inode *masterInode
	t     *Terminal
}

var _ vfs.FileDescriptionImpl = (*masterFileDescription)(nil)

// Release implements vfs.FileDescriptionImpl.Release.
func (mfd *masterFileDescription) Release() {
	mfd.inode.root.masterClose(mfd.t)
	mfd.inode.DecRef()
}

// EventRegister implements waiter.Waitable.EventRegister.
func (mfd *masterFileDescription) EventRegister(e *waiter.Entry, mask waiter.EventMask) {
	mfd.t.ld.masterWaiter.EventRegister(e, mask)
}

// EventUnregister implements waiter.Waitable.EventUnregister.
func (mfd *masterFileDescription) EventUnregister(e *waiter.Entry) {
	mfd.t.ld.masterWaiter.EventUnregister(e)
}

// Readiness implements waiter.Waitable.Readiness.
func (mfd *masterFileDescription) Readiness(mask waiter.EventMask) waiter.EventMask {
	return mfd.t.ld.masterReadiness()
}

// Read implements vfs.FileDescriptionImpl.Read.
func (mfd *masterFileDescription) Read(ctx context.Context, dst usermem.IOSequence, _ vfs.ReadOptions) (int64, error) {
	return mfd.t.ld.outputQueueRead(ctx, dst)
}

// Write implements vfs.FileDescriptionImpl.Write.
func (mfd *masterFileDescription) Write(ctx context.Context, src usermem.IOSequence, _ vfs.WriteOptions) (int64, error) {
	return mfd.t.ld.inputQueueWrite(ctx, src)
}

// Ioctl implements vfs.FileDescriptionImpl.Ioctl.
func (mfd *masterFileDescription) Ioctl(ctx context.Context, io usermem.IO, args arch.SyscallArguments) (uintptr, error) {
	switch cmd := args[1].Uint(); cmd {
	case linux.FIONREAD: // linux.FIONREAD == linux.TIOCINQ
		// Get the number of bytes in the output queue read buffer.
		return 0, mfd.t.ld.outputQueueReadSize(ctx, io, args)
	case linux.TCGETS:
		// N.B. TCGETS on the master actually returns the configuration
		// of the slave end.
		return mfd.t.ld.getTermios(ctx, io, args)
	case linux.TCSETS:
		// N.B. TCSETS on the master actually affects the configuration
		// of the slave end.
		return mfd.t.ld.setTermios(ctx, io, args)
	case linux.TCSETSW:
		// TODO(b/29356795): This should drain the output queue first.
		return mfd.t.ld.setTermios(ctx, io, args)
	case linux.TIOCGPTN:
		_, err := usermem.CopyObjectOut(ctx, io, args[2].Pointer(), uint32(mfd.t.n), usermem.IOOpts{
			AddressSpaceActive: true,
		})
		return 0, err
	case linux.TIOCSPTLCK:
		// TODO(b/29356795): Implement pty locking. For now just pretend we do.
		return 0, nil
	case linux.TIOCGWINSZ:
		return 0, mfd.t.ld.windowSize(ctx, io, args)
	case linux.TIOCSWINSZ:
		return 0, mfd.t.ld.setWindowSize(ctx, io, args)
	case linux.TIOCSCTTY:
		// Make the given terminal the controlling terminal of the
		// calling process.
		return 0, mfd.t.setControllingTTY(ctx, io, args, true /* isMaster */)
	case linux.TIOCNOTTY:
		// Release this process's controlling terminal.
		return 0, mfd.t.releaseControllingTTY(ctx, io, args, true /* isMaster */)
	case linux.TIOCGPGRP:
		// Get the foreground process group.
		return mfd.t.foregroundProcessGroup(ctx, io, args, true /* isMaster */)
	case linux.TIOCSPGRP:
		// Set the foreground process group.
		return mfd.t.setForegroundProcessGroup(ctx, io, args, true /* isMaster */)
	default:
		maybeEmitUnimplementedEvent(ctx, cmd)
		return 0, syserror.ENOTTY
	}
}

// SetStat implements vfs.FileDescriptionImpl.SetStat.
func (mfd *masterFileDescription) SetStat(ctx context.Context, opts vfs.SetStatOptions) error {
	creds := auth.CredentialsFromContext(ctx)
	fs := mfd.vfsfd.VirtualDentry().Mount().Filesystem()
	return mfd.inode.SetStat(ctx, fs, creds, opts)
}

// Stat implements vfs.FileDescriptionImpl.Stat.
func (mfd *masterFileDescription) Stat(ctx context.Context, opts vfs.StatOptions) (linux.Statx, error) {
	fs := mfd.vfsfd.VirtualDentry().Mount().Filesystem()
	return mfd.inode.Stat(ctx, fs, opts)
}

// LockPOSIX implements vfs.FileDescriptionImpl.LockPOSIX.
func (mfd *masterFileDescription) LockPOSIX(ctx context.Context, uid fslock.UniqueID, t fslock.LockType, start, length uint64, whence int16, block fslock.Blocker) error {
	return mfd.Locks().LockPOSIX(ctx, &mfd.vfsfd, uid, t, start, length, whence, block)
}

// UnlockPOSIX implements vfs.FileDescriptionImpl.UnlockPOSIX.
func (mfd *masterFileDescription) UnlockPOSIX(ctx context.Context, uid fslock.UniqueID, start, length uint64, whence int16) error {
	return mfd.Locks().UnlockPOSIX(ctx, &mfd.vfsfd, uid, start, length, whence)
}

// maybeEmitUnimplementedEvent emits unimplemented event if cmd is valid.
func maybeEmitUnimplementedEvent(ctx context.Context, cmd uint32) {
	switch cmd {
	case linux.TCGETS,
		linux.TCSETS,
		linux.TCSETSW,
		linux.TCSETSF,
		linux.TIOCGWINSZ,
		linux.TIOCSWINSZ,
		linux.TIOCSETD,
		linux.TIOCSBRK,
		linux.TIOCCBRK,
		linux.TCSBRK,
		linux.TCSBRKP,
		linux.TIOCSTI,
		linux.TIOCCONS,
		linux.FIONBIO,
		linux.TIOCEXCL,
		linux.TIOCNXCL,
		linux.TIOCGEXCL,
		linux.TIOCGSID,
		linux.TIOCGETD,
		linux.TIOCVHANGUP,
		linux.TIOCGDEV,
		linux.TIOCMGET,
		linux.TIOCMSET,
		linux.TIOCMBIC,
		linux.TIOCMBIS,
		linux.TIOCGICOUNT,
		linux.TCFLSH,
		linux.TIOCSSERIAL,
		linux.TIOCGPTPEER:

		unimpl.EmitUnimplementedEvent(ctx)
	}
}
