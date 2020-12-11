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

// Package signalfd provides basic signalfd file implementations.
package signalfd

import (
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/syserror"
	"gvisor.dev/gvisor/pkg/usermem"
	"gvisor.dev/gvisor/pkg/waiter"
)

// SignalFileDescription implements vfs.FileDescriptionImpl for signal fds.
//
// +stateify savable
type SignalFileDescription struct {
	vfsfd vfs.FileDescription
	vfs.FileDescriptionDefaultImpl
	vfs.DentryMetadataFileDescriptionImpl
	vfs.NoLockFD

	// target is the original signal target task.
	//
	// The semantics here are a bit broken. Linux will always use current
	// for all reads, regardless of where the signalfd originated. We can't
	// do exactly that because we need to plumb the context through
	// EventRegister in order to support proper blocking behavior. This
	// will undoubtedly become very complicated quickly.
	target *kernel.Task

	// mu protects mask.
	mu sync.Mutex `state:"nosave"`

	// mask is the signal mask. Protected by mu.
	mask linux.SignalSet
}

var _ vfs.FileDescriptionImpl = (*SignalFileDescription)(nil)

// New creates a new signal fd.
func New(vfsObj *vfs.VirtualFilesystem, target *kernel.Task, mask linux.SignalSet, flags uint32) (*vfs.FileDescription, error) {
	vd := vfsObj.NewAnonVirtualDentry("[signalfd]")
	defer vd.DecRef(target)
	sfd := &SignalFileDescription{
		target: target,
		mask:   mask,
	}
	if err := sfd.vfsfd.Init(sfd, flags, vd.Mount(), vd.Dentry(), &vfs.FileDescriptionOptions{
		UseDentryMetadata: true,
		DenyPRead:         true,
		DenyPWrite:        true,
	}); err != nil {
		return nil, err
	}
	return &sfd.vfsfd, nil
}

// Mask returns the signal mask.
func (sfd *SignalFileDescription) Mask() linux.SignalSet {
	sfd.mu.Lock()
	defer sfd.mu.Unlock()
	return sfd.mask
}

// SetMask sets the signal mask.
func (sfd *SignalFileDescription) SetMask(mask linux.SignalSet) {
	sfd.mu.Lock()
	defer sfd.mu.Unlock()
	sfd.mask = mask
}

// Read implements vfs.FileDescriptionImpl.Read.
func (sfd *SignalFileDescription) Read(ctx context.Context, dst usermem.IOSequence, _ vfs.ReadOptions) (int64, error) {
	// Attempt to dequeue relevant signals.
	info, err := sfd.target.Sigtimedwait(sfd.Mask(), 0)
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
func (sfd *SignalFileDescription) Readiness(mask waiter.EventMask) waiter.EventMask {
	sfd.mu.Lock()
	defer sfd.mu.Unlock()
	if mask&waiter.EventIn != 0 && sfd.target.PendingSignals()&sfd.mask != 0 {
		return waiter.EventIn // Pending signals.
	}
	return 0
}

// EventRegister implements waiter.Waitable.EventRegister.
func (sfd *SignalFileDescription) EventRegister(entry *waiter.Entry, _ waiter.EventMask) {
	sfd.mu.Lock()
	defer sfd.mu.Unlock()
	// Register for the signal set; ignore the passed events.
	sfd.target.SignalRegister(entry, waiter.EventMask(sfd.mask))
}

// EventUnregister implements waiter.Waitable.EventUnregister.
func (sfd *SignalFileDescription) EventUnregister(entry *waiter.Entry) {
	// Unregister the original entry.
	sfd.target.SignalUnregister(entry)
}

// Release implements vfs.FileDescriptionImpl.Release.
func (sfd *SignalFileDescription) Release(context.Context) {}
