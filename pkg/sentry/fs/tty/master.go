// Copyright 2018 Google LLC
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
	"gvisor.googlesource.com/gvisor/pkg/abi/linux"
	"gvisor.googlesource.com/gvisor/pkg/sentry/arch"
	"gvisor.googlesource.com/gvisor/pkg/sentry/context"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs/fsutil"
	"gvisor.googlesource.com/gvisor/pkg/sentry/usermem"
	"gvisor.googlesource.com/gvisor/pkg/syserror"
	"gvisor.googlesource.com/gvisor/pkg/waiter"
)

// masterInodeOperations are the fs.InodeOperations for the master end of the
// Terminal (ptmx file).
//
// +stateify savable
type masterInodeOperations struct {
	inodeOperations

	// d is the containing dir.
	d *dirInodeOperations
}

var _ fs.InodeOperations = (*masterInodeOperations)(nil)

// newMasterInode creates an Inode for the master end of a terminal.
func newMasterInode(ctx context.Context, d *dirInodeOperations, owner fs.FileOwner, p fs.FilePermissions) *fs.Inode {
	iops := &masterInodeOperations{
		inodeOperations: inodeOperations{
			uattr: fs.WithCurrentTime(ctx, fs.UnstableAttr{
				Owner: owner,
				Perms: p,
				Links: 1,
				// Size and Blocks are always 0.
			}),
		},
		d: d,
	}

	return fs.NewInode(iops, d.msrc, fs.StableAttr{
		DeviceID: ptsDevice.DeviceID(),
		// N.B. Linux always uses inode id 2 for ptmx. See
		// fs/devpts/inode.c:mknod_ptmx.
		//
		// TODO: Since ptsDevice must be shared between
		// different mounts, we must not assign fixed numbers.
		InodeID: ptsDevice.NextIno(),
		Type:    fs.CharacterDevice,
		// See fs/devpts/inode.c:devpts_fill_super.
		BlockSize: 1024,
		// The PTY master effectively has two different major/minor
		// device numbers.
		//
		// This one is returned by stat for both opened and unopened
		// instances of this inode.
		//
		// When the inode is opened (GetFile), a new device number is
		// allocated based on major UNIX98_PTY_MASTER_MAJOR and the tty
		// index as minor number. However, this device number is only
		// accessible via ioctl(TIOCGDEV) and /proc/TID/stat.
		DeviceFileMajor: linux.TTYAUX_MAJOR,
		DeviceFileMinor: linux.PTMX_MINOR,
	})
}

// Release implements fs.InodeOperations.Release.
func (mi *masterInodeOperations) Release(ctx context.Context) {
}

// GetFile implements fs.InodeOperations.GetFile.
//
// It allocates a new terminal.
func (mi *masterInodeOperations) GetFile(ctx context.Context, d *fs.Dirent, flags fs.FileFlags) (*fs.File, error) {
	t, err := mi.d.allocateTerminal(ctx)
	if err != nil {
		return nil, err
	}

	return fs.NewFile(ctx, d, flags, &masterFileOperations{
		d: mi.d,
		t: t,
	}), nil
}

// masterFileOperations are the fs.FileOperations for the master end of a terminal.
//
// +stateify savable
type masterFileOperations struct {
	fsutil.PipeSeek      `state:"nosave"`
	fsutil.NotDirReaddir `state:"nosave"`
	fsutil.NoFsync       `state:"nosave"`
	fsutil.NoopFlush     `state:"nosave"`
	fsutil.NoMMap        `state:"nosave"`

	// d is the containing dir.
	d *dirInodeOperations

	// t is the connected Terminal.
	t *Terminal
}

var _ fs.FileOperations = (*masterFileOperations)(nil)

// Release implements fs.FileOperations.Release.
func (mf *masterFileOperations) Release() {
	mf.d.masterClose(mf.t)
	mf.t.DecRef()
}

// EventRegister implements waiter.Waitable.EventRegister.
func (mf *masterFileOperations) EventRegister(e *waiter.Entry, mask waiter.EventMask) {
	mf.t.ld.masterWaiter.EventRegister(e, mask)
}

// EventUnregister implements waiter.Waitable.EventUnregister.
func (mf *masterFileOperations) EventUnregister(e *waiter.Entry) {
	mf.t.ld.masterWaiter.EventUnregister(e)
}

// Readiness implements waiter.Waitable.Readiness.
func (mf *masterFileOperations) Readiness(mask waiter.EventMask) waiter.EventMask {
	return mf.t.ld.masterReadiness()
}

// Read implements fs.FileOperations.Read.
func (mf *masterFileOperations) Read(ctx context.Context, _ *fs.File, dst usermem.IOSequence, _ int64) (int64, error) {
	return mf.t.ld.outputQueueRead(ctx, dst)
}

// Write implements fs.FileOperations.Write.
func (mf *masterFileOperations) Write(ctx context.Context, _ *fs.File, src usermem.IOSequence, _ int64) (int64, error) {
	return mf.t.ld.inputQueueWrite(ctx, src)
}

// Ioctl implements fs.FileOperations.Ioctl.
func (mf *masterFileOperations) Ioctl(ctx context.Context, io usermem.IO, args arch.SyscallArguments) (uintptr, error) {
	switch args[1].Uint() {
	case linux.FIONREAD: // linux.FIONREAD == linux.TIOCINQ
		// Get the number of bytes in the output queue read buffer.
		return 0, mf.t.ld.outputQueueReadSize(ctx, io, args)
	case linux.TCGETS:
		// N.B. TCGETS on the master actually returns the configuration
		// of the slave end.
		return mf.t.ld.getTermios(ctx, io, args)
	case linux.TCSETS:
		// N.B. TCSETS on the master actually affects the configuration
		// of the slave end.
		return mf.t.ld.setTermios(ctx, io, args)
	case linux.TCSETSW:
		// TODO: This should drain the output queue first.
		return mf.t.ld.setTermios(ctx, io, args)
	case linux.TIOCGPTN:
		_, err := usermem.CopyObjectOut(ctx, io, args[2].Pointer(), uint32(mf.t.n), usermem.IOOpts{
			AddressSpaceActive: true,
		})
		return 0, err
	case linux.TIOCSPTLCK:
		// TODO: Implement pty locking. For now just pretend we do.
		return 0, nil
	case linux.TIOCGWINSZ:
		return 0, mf.t.ld.windowSize(ctx, io, args)
	case linux.TIOCSWINSZ:
		return 0, mf.t.ld.setWindowSize(ctx, io, args)
	default:
		return 0, syserror.ENOTTY
	}
}
