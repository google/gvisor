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

// Package fasync provides FIOASYNC related functionality.
package fasync

import (
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/sentry/fs"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/syserror"
	"gvisor.dev/gvisor/pkg/waiter"
)

// Table to convert waiter event masks into si_band siginfo codes.
// Taken from fs/fcntl.c:band_table.
var bandTable = map[waiter.EventMask]int64{
	// POLL_IN
	waiter.EventIn: linux.EPOLLIN | linux.EPOLLRDNORM,
	// POLL_OUT
	waiter.EventOut: linux.EPOLLOUT | linux.EPOLLWRNORM | linux.EPOLLWRBAND,
	// POLL_ERR
	waiter.EventErr: linux.EPOLLERR,
	// POLL_PRI
	waiter.EventPri: linux.EPOLLPRI | linux.EPOLLRDBAND,
	// POLL_HUP
	waiter.EventHUp: linux.EPOLLHUP | linux.EPOLLERR,
}

// New returns a function that creates a new fs.FileAsync with the given file
// descriptor.
func New(fd int) func() fs.FileAsync {
	return func() fs.FileAsync {
		return &FileAsync{fd: fd}
	}
}

// NewVFS2 returns a function that creates a new vfs.FileAsync with the given
// file descriptor.
func NewVFS2(fd int) func() vfs.FileAsync {
	return func() vfs.FileAsync {
		return &FileAsync{fd: fd}
	}
}

// FileAsync sends signals when the registered file is ready for IO.
//
// +stateify savable
type FileAsync struct {
	// e is immutable after first use (which is protected by mu below).
	e waiter.Entry

	// fd is the file descriptor to notify about.
	// It is immutable, set at allocation time. This matches Linux semantics in
	// fs/fcntl.c:fasync_helper.
	// The fd value is passed to the signal recipient in siginfo.si_fd.
	fd int

	// regMu protects registeration and unregistration actions on e.
	//
	// regMu must be held while registration decisions are being made
	// through the registration action itself.
	//
	// Lock ordering: regMu, mu.
	regMu sync.Mutex `state:"nosave"`

	// mu protects all following fields.
	//
	// Lock ordering: e.mu, mu.
	mu         sync.Mutex `state:"nosave"`
	requester  *auth.Credentials
	registered bool
	// signal is the signal to deliver upon I/O being available.
	// The default value ("zero signal") means the default SIGIO signal will be
	// delivered.
	signal linux.Signal

	// Only one of the following is allowed to be non-nil.
	recipientPG *kernel.ProcessGroup
	recipientTG *kernel.ThreadGroup
	recipientT  *kernel.Task
}

// Callback sends a signal.
func (a *FileAsync) Callback(e *waiter.Entry, mask waiter.EventMask) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.registered {
		return
	}
	t := a.recipientT
	tg := a.recipientTG
	if a.recipientPG != nil {
		tg = a.recipientPG.Originator()
	}
	if tg != nil {
		t = tg.Leader()
	}
	if t == nil {
		// No recipient has been registered.
		return
	}
	c := t.Credentials()
	// Logic from sigio_perm in fs/fcntl.c.
	permCheck := (a.requester.EffectiveKUID == 0 ||
		a.requester.EffectiveKUID == c.SavedKUID ||
		a.requester.EffectiveKUID == c.RealKUID ||
		a.requester.RealKUID == c.SavedKUID ||
		a.requester.RealKUID == c.RealKUID)
	if !permCheck {
		return
	}
	signalInfo := &linux.SignalInfo{
		Signo: int32(linux.SIGIO),
		Code:  linux.SI_KERNEL,
	}
	if a.signal != 0 {
		signalInfo.Signo = int32(a.signal)
		signalInfo.SetFD(uint32(a.fd))
		var band int64
		for m, bandCode := range bandTable {
			if m&mask != 0 {
				band |= bandCode
			}
		}
		signalInfo.SetBand(band)
	}
	t.SendSignal(signalInfo)
}

// Register sets the file which will be monitored for IO events.
//
// The file must not be currently registered.
func (a *FileAsync) Register(w waiter.Waitable) {
	a.regMu.Lock()
	defer a.regMu.Unlock()
	a.mu.Lock()

	if a.registered {
		a.mu.Unlock()
		panic("registering already registered file")
	}

	if a.e.Callback == nil {
		a.e.Callback = a
	}
	a.registered = true

	a.mu.Unlock()
	w.EventRegister(&a.e, waiter.ReadableEvents|waiter.WritableEvents|waiter.EventErr|waiter.EventHUp)
}

// Unregister stops monitoring a file.
//
// The file must be currently registered.
func (a *FileAsync) Unregister(w waiter.Waitable) {
	a.regMu.Lock()
	defer a.regMu.Unlock()
	a.mu.Lock()

	if !a.registered {
		a.mu.Unlock()
		panic("unregistering unregistered file")
	}

	a.registered = false

	a.mu.Unlock()
	w.EventUnregister(&a.e)
}

// Owner returns who is currently getting signals. All return values will be
// nil if no one is set to receive signals.
func (a *FileAsync) Owner() (*kernel.Task, *kernel.ThreadGroup, *kernel.ProcessGroup) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.recipientT, a.recipientTG, a.recipientPG
}

// SetOwnerTask sets the owner (who will receive signals) to a specified task.
// Only this owner will receive signals.
func (a *FileAsync) SetOwnerTask(requester *kernel.Task, recipient *kernel.Task) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.requester = requester.Credentials()
	a.recipientT = recipient
	a.recipientTG = nil
	a.recipientPG = nil
}

// SetOwnerThreadGroup sets the owner (who will receive signals) to a specified
// thread group. Only this owner will receive signals.
func (a *FileAsync) SetOwnerThreadGroup(requester *kernel.Task, recipient *kernel.ThreadGroup) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.requester = requester.Credentials()
	a.recipientT = nil
	a.recipientTG = recipient
	a.recipientPG = nil
}

// SetOwnerProcessGroup sets the owner (who will receive signals) to a
// specified process group. Only this owner will receive signals.
func (a *FileAsync) SetOwnerProcessGroup(requester *kernel.Task, recipient *kernel.ProcessGroup) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.requester = requester.Credentials()
	a.recipientT = nil
	a.recipientTG = nil
	a.recipientPG = recipient
}

// ClearOwner unsets the current signal recipient.
func (a *FileAsync) ClearOwner() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.requester = nil
	a.recipientT = nil
	a.recipientTG = nil
	a.recipientPG = nil
}

// Signal returns which signal will be sent to the signal recipient.
// A value of zero means the signal to deliver wasn't customized, which means
// the default signal (SIGIO) will be delivered.
func (a *FileAsync) Signal() linux.Signal {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.signal
}

// SetSignal overrides which signal to send when I/O is available.
// The default behavior can be reset by specifying signal zero, which means
// to send SIGIO.
func (a *FileAsync) SetSignal(signal linux.Signal) error {
	if signal != 0 && !signal.IsValid() {
		return syserror.EINVAL
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.signal = signal
	return nil
}
