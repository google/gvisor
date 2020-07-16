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
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/syserror"
	"gvisor.dev/gvisor/pkg/usermem"
	"gvisor.dev/gvisor/pkg/waiter"
)

// slaveInode is the inode for the slave end of the Terminal.
type slaveInode struct {
	kernfs.InodeAttrs
	kernfs.InodeNoopRefCount
	kernfs.InodeNotDirectory
	kernfs.InodeNotSymlink

	locks vfs.FileLocks

	// Keep a reference to this inode's dentry.
	dentry kernfs.Dentry

	// root is the devpts root inode.
	root *rootInode

	// t is the connected Terminal.
	t *Terminal
}

var _ kernfs.Inode = (*slaveInode)(nil)

// Open implements kernfs.Inode.Open.
func (si *slaveInode) Open(ctx context.Context, rp *vfs.ResolvingPath, vfsd *vfs.Dentry, opts vfs.OpenOptions) (*vfs.FileDescription, error) {
	si.IncRef()
	fd := &slaveFileDescription{
		inode: si,
	}
	fd.LockFD.Init(&si.locks)
	if err := fd.vfsfd.Init(fd, opts.Flags, rp.Mount(), vfsd, &vfs.FileDescriptionOptions{}); err != nil {
		si.DecRef()
		return nil, err
	}
	return &fd.vfsfd, nil

}

// Valid implements kernfs.Inode.Valid.
func (si *slaveInode) Valid(context.Context) bool {
	// Return valid if the slave still exists.
	si.root.mu.Lock()
	defer si.root.mu.Unlock()
	_, ok := si.root.slaves[si.t.n]
	return ok
}

// Stat implements kernfs.Inode.Stat.
func (si *slaveInode) Stat(ctx context.Context, vfsfs *vfs.Filesystem, opts vfs.StatOptions) (linux.Statx, error) {
	statx, err := si.InodeAttrs.Stat(ctx, vfsfs, opts)
	if err != nil {
		return linux.Statx{}, err
	}
	statx.Blksize = 1024
	statx.RdevMajor = linux.UNIX98_PTY_SLAVE_MAJOR
	statx.RdevMinor = si.t.n
	return statx, nil
}

// SetStat implements kernfs.Inode.SetStat
func (si *slaveInode) SetStat(ctx context.Context, vfsfs *vfs.Filesystem, creds *auth.Credentials, opts vfs.SetStatOptions) error {
	if opts.Stat.Mask&linux.STATX_SIZE != 0 {
		return syserror.EINVAL
	}
	return si.InodeAttrs.SetStat(ctx, vfsfs, creds, opts)
}

type slaveFileDescription struct {
	vfsfd vfs.FileDescription
	vfs.FileDescriptionDefaultImpl
	vfs.LockFD

	inode *slaveInode
}

var _ vfs.FileDescriptionImpl = (*slaveFileDescription)(nil)

// Release implements fs.FileOperations.Release.
func (sfd *slaveFileDescription) Release() {
	sfd.inode.DecRef()
}

// EventRegister implements waiter.Waitable.EventRegister.
func (sfd *slaveFileDescription) EventRegister(e *waiter.Entry, mask waiter.EventMask) {
	sfd.inode.t.ld.slaveWaiter.EventRegister(e, mask)
}

// EventUnregister implements waiter.Waitable.EventUnregister.
func (sfd *slaveFileDescription) EventUnregister(e *waiter.Entry) {
	sfd.inode.t.ld.slaveWaiter.EventUnregister(e)
}

// Readiness implements waiter.Waitable.Readiness.
func (sfd *slaveFileDescription) Readiness(mask waiter.EventMask) waiter.EventMask {
	return sfd.inode.t.ld.slaveReadiness()
}

// Read implements vfs.FileDescriptionImpl.Read.
func (sfd *slaveFileDescription) Read(ctx context.Context, dst usermem.IOSequence, _ vfs.ReadOptions) (int64, error) {
	return sfd.inode.t.ld.inputQueueRead(ctx, dst)
}

// Write implements vfs.FileDescriptionImpl.Write.
func (sfd *slaveFileDescription) Write(ctx context.Context, src usermem.IOSequence, _ vfs.WriteOptions) (int64, error) {
	return sfd.inode.t.ld.outputQueueWrite(ctx, src)
}

// Ioctl implements vfs.FileDescripionImpl.Ioctl.
func (sfd *slaveFileDescription) Ioctl(ctx context.Context, io usermem.IO, args arch.SyscallArguments) (uintptr, error) {
	switch cmd := args[1].Uint(); cmd {
	case linux.FIONREAD: // linux.FIONREAD == linux.TIOCINQ
		// Get the number of bytes in the input queue read buffer.
		return 0, sfd.inode.t.ld.inputQueueReadSize(ctx, io, args)
	case linux.TCGETS:
		return sfd.inode.t.ld.getTermios(ctx, io, args)
	case linux.TCSETS:
		return sfd.inode.t.ld.setTermios(ctx, io, args)
	case linux.TCSETSW:
		// TODO(b/29356795): This should drain the output queue first.
		return sfd.inode.t.ld.setTermios(ctx, io, args)
	case linux.TIOCGPTN:
		_, err := usermem.CopyObjectOut(ctx, io, args[2].Pointer(), uint32(sfd.inode.t.n), usermem.IOOpts{
			AddressSpaceActive: true,
		})
		return 0, err
	case linux.TIOCGWINSZ:
		return 0, sfd.inode.t.ld.windowSize(ctx, io, args)
	case linux.TIOCSWINSZ:
		return 0, sfd.inode.t.ld.setWindowSize(ctx, io, args)
	case linux.TIOCSCTTY:
		// Make the given terminal the controlling terminal of the
		// calling process.
		return 0, sfd.inode.t.setControllingTTY(ctx, io, args, false /* isMaster */)
	case linux.TIOCNOTTY:
		// Release this process's controlling terminal.
		return 0, sfd.inode.t.releaseControllingTTY(ctx, io, args, false /* isMaster */)
	case linux.TIOCGPGRP:
		// Get the foreground process group.
		return sfd.inode.t.foregroundProcessGroup(ctx, io, args, false /* isMaster */)
	case linux.TIOCSPGRP:
		// Set the foreground process group.
		return sfd.inode.t.setForegroundProcessGroup(ctx, io, args, false /* isMaster */)
	default:
		maybeEmitUnimplementedEvent(ctx, cmd)
		return 0, syserror.ENOTTY
	}
}

// SetStat implements vfs.FileDescriptionImpl.SetStat.
func (sfd *slaveFileDescription) SetStat(ctx context.Context, opts vfs.SetStatOptions) error {
	creds := auth.CredentialsFromContext(ctx)
	fs := sfd.vfsfd.VirtualDentry().Mount().Filesystem()
	return sfd.inode.SetStat(ctx, fs, creds, opts)
}

// Stat implements vfs.FileDescriptionImpl.Stat.
func (sfd *slaveFileDescription) Stat(ctx context.Context, opts vfs.StatOptions) (linux.Statx, error) {
	fs := sfd.vfsfd.VirtualDentry().Mount().Filesystem()
	return sfd.inode.Stat(ctx, fs, opts)
}

// LockPOSIX implements vfs.FileDescriptionImpl.LockPOSIX.
func (sfd *slaveFileDescription) LockPOSIX(ctx context.Context, uid fslock.UniqueID, t fslock.LockType, start, length uint64, whence int16, block fslock.Blocker) error {
	return sfd.Locks().LockPOSIX(ctx, &sfd.vfsfd, uid, t, start, length, whence, block)
}

// UnlockPOSIX implements vfs.FileDescriptionImpl.UnlockPOSIX.
func (sfd *slaveFileDescription) UnlockPOSIX(ctx context.Context, uid fslock.UniqueID, start, length uint64, whence int16) error {
	return sfd.Locks().UnlockPOSIX(ctx, &sfd.vfsfd, uid, start, length, whence)
}
