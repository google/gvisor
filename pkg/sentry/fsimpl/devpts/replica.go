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
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/marshal/primitive"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/kernfs"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/usermem"
	"gvisor.dev/gvisor/pkg/waiter"
)

// replicaInode is the inode for the replica end of the Terminal.
//
// +stateify savable
type replicaInode struct {
	implStatFS
	kernfs.InodeAttrs
	kernfs.InodeNoopRefCount
	kernfs.InodeNotDirectory
	kernfs.InodeNotSymlink
	kernfs.InodeWatches

	locks vfs.FileLocks

	// root is the devpts root inode.
	root *rootInode

	// t is the connected Terminal.
	t *Terminal
}

var _ kernfs.Inode = (*replicaInode)(nil)

// Open implements kernfs.Inode.Open.
func (ri *replicaInode) Open(ctx context.Context, rp *vfs.ResolvingPath, d *kernfs.Dentry, opts vfs.OpenOptions) (*vfs.FileDescription, error) {
	fd := &replicaFileDescription{
		inode: ri,
	}
	fd.LockFD.Init(&ri.locks)
	if err := fd.vfsfd.Init(fd, opts.Flags, rp.Mount(), d.VFSDentry(), &vfs.FileDescriptionOptions{}); err != nil {
		return nil, err
	}
	if opts.Flags&linux.O_NOCTTY == 0 {
		// Opening a replica sets the process' controlling TTY when
		// possible. An error indicates it cannot be set, and is
		// ignored silently.
		_ = fd.inode.t.setControllingTTY(ctx, false /* steal */, false /* isMaster */, fd.vfsfd.IsReadable())
	}
	return &fd.vfsfd, nil

}

// Valid implements kernfs.Inode.Valid.
func (ri *replicaInode) Valid(context.Context) bool {
	// Return valid if the replica still exists.
	ri.root.mu.Lock()
	defer ri.root.mu.Unlock()
	_, ok := ri.root.replicas[ri.t.n]
	return ok
}

// Stat implements kernfs.Inode.Stat.
func (ri *replicaInode) Stat(ctx context.Context, vfsfs *vfs.Filesystem, opts vfs.StatOptions) (linux.Statx, error) {
	statx, err := ri.InodeAttrs.Stat(ctx, vfsfs, opts)
	if err != nil {
		return linux.Statx{}, err
	}
	statx.Blksize = 1024
	statx.RdevMajor = linux.UNIX98_PTY_REPLICA_MAJOR
	statx.RdevMinor = ri.t.n
	return statx, nil
}

// SetStat implements kernfs.Inode.SetStat
func (ri *replicaInode) SetStat(ctx context.Context, vfsfs *vfs.Filesystem, creds *auth.Credentials, opts vfs.SetStatOptions) error {
	if opts.Stat.Mask&linux.STATX_SIZE != 0 {
		return linuxerr.EINVAL
	}
	return ri.InodeAttrs.SetStat(ctx, vfsfs, creds, opts)
}

// +stateify savable
type replicaFileDescription struct {
	vfsfd vfs.FileDescription
	vfs.FileDescriptionDefaultImpl
	vfs.LockFD

	inode *replicaInode
}

var _ vfs.FileDescriptionImpl = (*replicaFileDescription)(nil)

// Release implements fs.FileOperations.Release.
func (rfd *replicaFileDescription) Release(ctx context.Context) {}

// EventRegister implements waiter.Waitable.EventRegister.
func (rfd *replicaFileDescription) EventRegister(e *waiter.Entry) error {
	rfd.inode.t.ld.replicaWaiter.EventRegister(e)
	return nil
}

// EventUnregister implements waiter.Waitable.EventUnregister.
func (rfd *replicaFileDescription) EventUnregister(e *waiter.Entry) {
	rfd.inode.t.ld.replicaWaiter.EventUnregister(e)
}

// Readiness implements waiter.Waitable.Readiness.
func (rfd *replicaFileDescription) Readiness(mask waiter.EventMask) waiter.EventMask {
	return rfd.inode.t.ld.replicaReadiness()
}

// Epollable implements FileDescriptionImpl.Epollable.
func (rfd *replicaFileDescription) Epollable() bool {
	return true
}

// Read implements vfs.FileDescriptionImpl.Read.
func (rfd *replicaFileDescription) Read(ctx context.Context, dst usermem.IOSequence, _ vfs.ReadOptions) (int64, error) {
	return rfd.inode.t.ld.inputQueueRead(ctx, dst)
}

// Write implements vfs.FileDescriptionImpl.Write.
func (rfd *replicaFileDescription) Write(ctx context.Context, src usermem.IOSequence, _ vfs.WriteOptions) (int64, error) {
	return rfd.inode.t.ld.outputQueueWrite(ctx, src)
}

// Ioctl implements vfs.FileDescriptionImpl.Ioctl.
func (rfd *replicaFileDescription) Ioctl(ctx context.Context, io usermem.IO, args arch.SyscallArguments) (uintptr, error) {
	t := kernel.TaskFromContext(ctx)
	if t == nil {
		// ioctl(2) may only be called from a task goroutine.
		return 0, linuxerr.ENOTTY
	}

	switch cmd := args[1].Uint(); cmd {
	case linux.FIONREAD: // linux.FIONREAD == linux.TIOCINQ
		// Get the number of bytes in the input queue read buffer.
		return 0, rfd.inode.t.ld.inputQueueReadSize(t, io, args)
	case linux.TCGETS:
		return rfd.inode.t.ld.getTermios(t, args)
	case linux.TCSETS:
		return rfd.inode.t.ld.setTermios(t, args)
	case linux.TCSETSW:
		// TODO(b/29356795): This should drain the output queue first.
		return rfd.inode.t.ld.setTermios(t, args)
	case linux.TIOCGPTN:
		nP := primitive.Uint32(rfd.inode.t.n)
		_, err := nP.CopyOut(t, args[2].Pointer())
		return 0, err
	case linux.TIOCGWINSZ:
		return 0, rfd.inode.t.ld.windowSize(t, args)
	case linux.TIOCSWINSZ:
		return 0, rfd.inode.t.ld.setWindowSize(t, args)
	case linux.TIOCSCTTY:
		// Make the given terminal the controlling terminal of the
		// calling process.
		steal := args[2].Int() == 1
		return 0, rfd.inode.t.setControllingTTY(ctx, steal, false /* isMaster */, rfd.vfsfd.IsReadable())
	case linux.TIOCNOTTY:
		// Release this process's controlling terminal.
		return 0, rfd.inode.t.releaseControllingTTY(ctx, false /* isMaster */)
	case linux.TIOCGPGRP:
		// Get the foreground process group.
		return rfd.inode.t.foregroundProcessGroup(ctx, args, false /* isMaster */)
	case linux.TIOCSPGRP:
		// Set the foreground process group.
		return rfd.inode.t.setForegroundProcessGroup(ctx, args, false /* isMaster */)
	default:
		maybeEmitUnimplementedEvent(ctx, cmd)
		return 0, linuxerr.ENOTTY
	}
}

// SetStat implements vfs.FileDescriptionImpl.SetStat.
func (rfd *replicaFileDescription) SetStat(ctx context.Context, opts vfs.SetStatOptions) error {
	creds := auth.CredentialsFromContext(ctx)
	fs := rfd.vfsfd.VirtualDentry().Mount().Filesystem()
	return rfd.inode.SetStat(ctx, fs, creds, opts)
}

// Stat implements vfs.FileDescriptionImpl.Stat.
func (rfd *replicaFileDescription) Stat(ctx context.Context, opts vfs.StatOptions) (linux.Statx, error) {
	fs := rfd.vfsfd.VirtualDentry().Mount().Filesystem()
	return rfd.inode.Stat(ctx, fs, opts)
}
