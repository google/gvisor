// Copyright 2019 The gVisor Authors.
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

// Package signalfd provides an implementation of signal file descriptors.
package signalfd

import (
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/sentry/fs"
	"gvisor.dev/gvisor/pkg/sentry/fs/anon"
	"gvisor.dev/gvisor/pkg/sentry/fs/fsutil"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/syserror"
	"gvisor.dev/gvisor/pkg/usermem"
	"gvisor.dev/gvisor/pkg/waiter"
)

// SignalOperations represent a file with signalfd semantics.
//
// +stateify savable
type SignalOperations struct {
	fsutil.FileNoopRelease          `state:"nosave"`
	fsutil.FilePipeSeek             `state:"nosave"`
	fsutil.FileNotDirReaddir        `state:"nosave"`
	fsutil.FileNoIoctl              `state:"nosave"`
	fsutil.FileNoFsync              `state:"nosave"`
	fsutil.FileNoMMap               `state:"nosave"`
	fsutil.FileNoSplice             `state:"nosave"`
	fsutil.FileNoWrite              `state:"nosave"`
	fsutil.FileNoopFlush            `state:"nosave"`
	fsutil.FileUseInodeUnstableAttr `state:"nosave"`

	// target is the original task target.
	//
	// The semantics here are a bit broken. Linux will always use current
	// for all reads, regardless of where the signalfd originated. We can't
	// do exactly that because we need to plumb the context through
	// EventRegister in order to support proper blocking behavior. This
	// will undoubtedly become very complicated quickly.
	target *kernel.Task

	// mu protects below.
	mu sync.Mutex `state:"nosave"`

	// mask is the signal mask. Protected by mu.
	mask linux.SignalSet
}

// New creates a new signalfd object with the supplied mask.
func New(ctx context.Context, mask linux.SignalSet) (*fs.File, error) {
	t := kernel.TaskFromContext(ctx)
	if t == nil {
		// No task context? Not valid.
		return nil, syserror.EINVAL
	}
	// name matches fs/signalfd.c:signalfd4.
	dirent := fs.NewDirent(ctx, anon.NewInode(ctx), "anon_inode:[signalfd]")
	return fs.NewFile(ctx, dirent, fs.FileFlags{Read: true, Write: true}, &SignalOperations{
		target: t,
		mask:   mask,
	}), nil
}

// Release implements fs.FileOperations.Release.
func (s *SignalOperations) Release(context.Context) {}

// Mask returns the signal mask.
func (s *SignalOperations) Mask() linux.SignalSet {
	s.mu.Lock()
	mask := s.mask
	s.mu.Unlock()
	return mask
}

// SetMask sets the signal mask.
func (s *SignalOperations) SetMask(mask linux.SignalSet) {
	s.mu.Lock()
	s.mask = mask
	s.mu.Unlock()
}

// Read implements fs.FileOperations.Read.
func (s *SignalOperations) Read(ctx context.Context, _ *fs.File, dst usermem.IOSequence, _ int64) (int64, error) {
	// Attempt to dequeue relevant signals.
	info, err := s.target.Sigtimedwait(s.Mask(), 0)
	if err != nil {
		// There must be no signal available.
		return 0, syserror.ErrWouldBlock
	}

	// Copy out the signal info using the specified format.
	infoNative := linux.SignalfdSiginfo{
		Signo:   uint32(info.Signo),
		Errno:   info.Errno,
		Code:    info.Code,
		PID:     uint32(info.PID()),
		UID:     uint32(info.UID()),
		Status:  info.Status(),
		Overrun: uint32(info.Overrun()),
		Addr:    info.Addr(),
	}
	n, err := infoNative.WriteTo(dst.Writer(ctx))
	if err == usermem.ErrEndOfIOSequence {
		// Partial copy-out ok.
		err = nil
	}
	return n, err
}

// Readiness implements waiter.Waitable.Readiness.
func (s *SignalOperations) Readiness(mask waiter.EventMask) waiter.EventMask {
	if mask&waiter.ReadableEvents != 0 && s.target.PendingSignals()&s.Mask() != 0 {
		return waiter.ReadableEvents // Pending signals.
	}
	return 0
}

// EventRegister implements waiter.Waitable.EventRegister.
func (s *SignalOperations) EventRegister(entry *waiter.Entry, _ waiter.EventMask) {
	// Register for the signal set; ignore the passed events.
	s.target.SignalRegister(entry, waiter.EventMask(s.Mask()))
}

// EventUnregister implements waiter.Waitable.EventUnregister.
func (s *SignalOperations) EventUnregister(entry *waiter.Entry) {
	// Unregister the original entry.
	s.target.SignalUnregister(entry)
}
