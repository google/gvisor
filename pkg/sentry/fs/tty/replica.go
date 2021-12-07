// Copyright 2018 The gVisor Authors.
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

package tty

import (
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/marshal/primitive"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/fs"
	"gvisor.dev/gvisor/pkg/sentry/fs/fsutil"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/usermem"
	"gvisor.dev/gvisor/pkg/waiter"
)

// LINT.IfChange

// replicaInodeOperations are the fs.InodeOperations for the replica end of the
// Terminal (pts file).
//
// +stateify savable
type replicaInodeOperations struct {
	fsutil.SimpleFileInode

	// d is the containing dir.
	d *dirInodeOperations

	// t is the connected Terminal.
	t *Terminal
}

var _ fs.InodeOperations = (*replicaInodeOperations)(nil)

// newReplicaInode creates an fs.Inode for the replica end of a terminal.
//
// newReplicaInode takes ownership of t.
func newReplicaInode(ctx context.Context, d *dirInodeOperations, t *Terminal, owner fs.FileOwner, p fs.FilePermissions) *fs.Inode {
	iops := &replicaInodeOperations{
		SimpleFileInode: *fsutil.NewSimpleFileInode(ctx, owner, p, linux.DEVPTS_SUPER_MAGIC),
		d:               d,
		t:               t,
	}

	return fs.NewInode(ctx, iops, d.msrc, fs.StableAttr{
		DeviceID: ptsDevice.DeviceID(),
		// N.B. Linux always uses inode id = tty index + 3. See
		// fs/devpts/inode.c:devpts_pty_new.
		//
		// TODO(b/75267214): Since ptsDevice must be shared between
		// different mounts, we must not assign fixed numbers.
		InodeID: ptsDevice.NextIno(),
		Type:    fs.CharacterDevice,
		// See fs/devpts/inode.c:devpts_fill_super.
		BlockSize:       1024,
		DeviceFileMajor: linux.UNIX98_PTY_REPLICA_MAJOR,
		DeviceFileMinor: t.n,
	})
}

// Release implements fs.InodeOperations.Release.
func (si *replicaInodeOperations) Release(ctx context.Context) {
	si.t.DecRef(ctx)
}

// Truncate implements fs.InodeOperations.Truncate.
func (*replicaInodeOperations) Truncate(context.Context, *fs.Inode, int64) error {
	return nil
}

// GetFile implements fs.InodeOperations.GetFile.
//
// This may race with destruction of the terminal. If the terminal is gone, it
// returns ENOENT.
func (si *replicaInodeOperations) GetFile(ctx context.Context, d *fs.Dirent, flags fs.FileFlags) (*fs.File, error) {
	return fs.NewFile(ctx, d, flags, &replicaFileOperations{si: si}), nil
}

// replicaFileOperations are the fs.FileOperations for the replica end of a
// terminal.
//
// +stateify savable
type replicaFileOperations struct {
	fsutil.FilePipeSeek             `state:"nosave"`
	fsutil.FileNotDirReaddir        `state:"nosave"`
	fsutil.FileNoFsync              `state:"nosave"`
	fsutil.FileNoMMap               `state:"nosave"`
	fsutil.FileNoSplice             `state:"nosave"`
	fsutil.FileNoopFlush            `state:"nosave"`
	fsutil.FileUseInodeUnstableAttr `state:"nosave"`

	// si is the inode operations.
	si *replicaInodeOperations
}

var _ fs.FileOperations = (*replicaFileOperations)(nil)

// Release implements fs.FileOperations.Release.
func (sf *replicaFileOperations) Release(context.Context) {
}

// EventRegister implements waiter.Waitable.EventRegister.
func (sf *replicaFileOperations) EventRegister(e *waiter.Entry) error {
	sf.si.t.ld.replicaWaiter.EventRegister(e)
	return nil
}

// EventUnregister implements waiter.Waitable.EventUnregister.
func (sf *replicaFileOperations) EventUnregister(e *waiter.Entry) {
	sf.si.t.ld.replicaWaiter.EventUnregister(e)
}

// Readiness implements waiter.Waitable.Readiness.
func (sf *replicaFileOperations) Readiness(mask waiter.EventMask) waiter.EventMask {
	return sf.si.t.ld.replicaReadiness()
}

// Read implements fs.FileOperations.Read.
func (sf *replicaFileOperations) Read(ctx context.Context, _ *fs.File, dst usermem.IOSequence, _ int64) (int64, error) {
	return sf.si.t.ld.inputQueueRead(ctx, dst)
}

// Write implements fs.FileOperations.Write.
func (sf *replicaFileOperations) Write(ctx context.Context, _ *fs.File, src usermem.IOSequence, _ int64) (int64, error) {
	return sf.si.t.ld.outputQueueWrite(ctx, src)
}

// Ioctl implements fs.FileOperations.Ioctl.
func (sf *replicaFileOperations) Ioctl(ctx context.Context, file *fs.File, io usermem.IO, args arch.SyscallArguments) (uintptr, error) {
	t := kernel.TaskFromContext(ctx)
	if t == nil {
		// ioctl(2) may only be called from a task goroutine.
		return 0, linuxerr.ENOTTY
	}

	switch cmd := args[1].Uint(); cmd {
	case linux.FIONREAD: // linux.FIONREAD == linux.TIOCINQ
		// Get the number of bytes in the input queue read buffer.
		return 0, sf.si.t.ld.inputQueueReadSize(t, args)
	case linux.TCGETS:
		return sf.si.t.ld.getTermios(t, args)
	case linux.TCSETS:
		return sf.si.t.ld.setTermios(t, args)
	case linux.TCSETSW:
		// TODO(b/29356795): This should drain the output queue first.
		return sf.si.t.ld.setTermios(t, args)
	case linux.TIOCGPTN:
		nP := primitive.Uint32(sf.si.t.n)
		_, err := nP.CopyOut(t, args[2].Pointer())
		return 0, err
	case linux.TIOCGWINSZ:
		return 0, sf.si.t.ld.windowSize(t, args)
	case linux.TIOCSWINSZ:
		return 0, sf.si.t.ld.setWindowSize(t, args)
	case linux.TIOCSCTTY:
		// Make the given terminal the controlling terminal of the
		// calling process.
		return 0, sf.si.t.setControllingTTY(ctx, args, false /* isMaster */, file.Flags().Read)
	case linux.TIOCNOTTY:
		// Release this process's controlling terminal.
		return 0, sf.si.t.releaseControllingTTY(ctx, args, false /* isMaster */)
	case linux.TIOCGPGRP:
		// Get the foreground process group.
		return sf.si.t.foregroundProcessGroup(ctx, args, false /* isMaster */)
	case linux.TIOCSPGRP:
		// Set the foreground process group.
		return sf.si.t.setForegroundProcessGroup(ctx, args, false /* isMaster */)
	default:
		maybeEmitUnimplementedEvent(ctx, cmd)
		return 0, linuxerr.ENOTTY
	}
}

// LINT.ThenChange(../../fsimpl/devpts/replica.go)
