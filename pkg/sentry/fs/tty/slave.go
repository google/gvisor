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
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/context"
	"gvisor.dev/gvisor/pkg/sentry/fs"
	"gvisor.dev/gvisor/pkg/sentry/fs/fsutil"
	"gvisor.dev/gvisor/pkg/sentry/usermem"
	"gvisor.dev/gvisor/pkg/syserror"
	"gvisor.dev/gvisor/pkg/waiter"
)

// slaveInodeOperations are the fs.InodeOperations for the slave end of the
// Terminal (pts file).
//
// +stateify savable
type slaveInodeOperations struct {
	fsutil.SimpleFileInode

	// d is the containing dir.
	d *dirInodeOperations

	// t is the connected Terminal.
	t *Terminal
}

var _ fs.InodeOperations = (*slaveInodeOperations)(nil)

// newSlaveInode creates an fs.Inode for the slave end of a terminal.
//
// newSlaveInode takes ownership of t.
func newSlaveInode(ctx context.Context, d *dirInodeOperations, t *Terminal, owner fs.FileOwner, p fs.FilePermissions) *fs.Inode {
	iops := &slaveInodeOperations{
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
		DeviceFileMajor: linux.UNIX98_PTY_SLAVE_MAJOR,
		DeviceFileMinor: t.n,
	})
}

// Release implements fs.InodeOperations.Release.
func (si *slaveInodeOperations) Release(ctx context.Context) {
	si.t.DecRef()
}

// Truncate implements fs.InodeOperations.Truncate.
func (slaveInodeOperations) Truncate(context.Context, *fs.Inode, int64) error {
	return nil
}

// GetFile implements fs.InodeOperations.GetFile.
//
// This may race with destruction of the terminal. If the terminal is gone, it
// returns ENOENT.
func (si *slaveInodeOperations) GetFile(ctx context.Context, d *fs.Dirent, flags fs.FileFlags) (*fs.File, error) {
	return fs.NewFile(ctx, d, flags, &slaveFileOperations{si: si}), nil
}

// slaveFileOperations are the fs.FileOperations for the slave end of a terminal.
//
// +stateify savable
type slaveFileOperations struct {
	fsutil.FilePipeSeek             `state:"nosave"`
	fsutil.FileNotDirReaddir        `state:"nosave"`
	fsutil.FileNoFsync              `state:"nosave"`
	fsutil.FileNoMMap               `state:"nosave"`
	fsutil.FileNoSplice             `state:"nosave"`
	fsutil.FileNoopFlush            `state:"nosave"`
	fsutil.FileUseInodeUnstableAttr `state:"nosave"`

	// si is the inode operations.
	si *slaveInodeOperations
}

var _ fs.FileOperations = (*slaveFileOperations)(nil)

// Release implements fs.FileOperations.Release.
func (sf *slaveFileOperations) Release() {
}

// EventRegister implements waiter.Waitable.EventRegister.
func (sf *slaveFileOperations) EventRegister(e *waiter.Entry, mask waiter.EventMask) {
	sf.si.t.ld.slaveWaiter.EventRegister(e, mask)
}

// EventUnregister implements waiter.Waitable.EventUnregister.
func (sf *slaveFileOperations) EventUnregister(e *waiter.Entry) {
	sf.si.t.ld.slaveWaiter.EventUnregister(e)
}

// Readiness implements waiter.Waitable.Readiness.
func (sf *slaveFileOperations) Readiness(mask waiter.EventMask) waiter.EventMask {
	return sf.si.t.ld.slaveReadiness()
}

// Read implements fs.FileOperations.Read.
func (sf *slaveFileOperations) Read(ctx context.Context, _ *fs.File, dst usermem.IOSequence, _ int64) (int64, error) {
	return sf.si.t.ld.inputQueueRead(ctx, dst)
}

// Write implements fs.FileOperations.Write.
func (sf *slaveFileOperations) Write(ctx context.Context, _ *fs.File, src usermem.IOSequence, _ int64) (int64, error) {
	return sf.si.t.ld.outputQueueWrite(ctx, src)
}

// Ioctl implements fs.FileOperations.Ioctl.
func (sf *slaveFileOperations) Ioctl(ctx context.Context, _ *fs.File, io usermem.IO, args arch.SyscallArguments) (uintptr, error) {
	switch cmd := args[1].Uint(); cmd {
	case linux.FIONREAD: // linux.FIONREAD == linux.TIOCINQ
		// Get the number of bytes in the input queue read buffer.
		return 0, sf.si.t.ld.inputQueueReadSize(ctx, io, args)
	case linux.TCGETS:
		return sf.si.t.ld.getTermios(ctx, io, args)
	case linux.TCSETS:
		return sf.si.t.ld.setTermios(ctx, io, args)
	case linux.TCSETSW:
		// TODO(b/29356795): This should drain the output queue first.
		return sf.si.t.ld.setTermios(ctx, io, args)
	case linux.TIOCGPTN:
		_, err := usermem.CopyObjectOut(ctx, io, args[2].Pointer(), uint32(sf.si.t.n), usermem.IOOpts{
			AddressSpaceActive: true,
		})
		return 0, err
	case linux.TIOCGWINSZ:
		return 0, sf.si.t.ld.windowSize(ctx, io, args)
	case linux.TIOCSWINSZ:
		return 0, sf.si.t.ld.setWindowSize(ctx, io, args)
	case linux.TIOCSCTTY:
		// Make the given terminal the controlling terminal of the
		// calling process.
		return 0, sf.si.t.setControllingTTY(ctx, io, args, false /* isMaster */)
	case linux.TIOCNOTTY:
		// Release this process's controlling terminal.
		return 0, sf.si.t.releaseControllingTTY(ctx, io, args, false /* isMaster */)
	case linux.TIOCGPGRP:
		// Get the foreground process group.
		return sf.si.t.foregroundProcessGroup(ctx, io, args, false /* isMaster */)
	case linux.TIOCSPGRP:
		// Set the foreground process group.
		return sf.si.t.setForegroundProcessGroup(ctx, io, args, false /* isMaster */)
	default:
		maybeEmitUnimplementedEvent(ctx, cmd)
		return 0, syserror.ENOTTY
	}
}
