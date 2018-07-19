// Copyright 2018 Google Inc.
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
	"sync"

	"gvisor.googlesource.com/gvisor/pkg/abi/linux"
	"gvisor.googlesource.com/gvisor/pkg/sentry/arch"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs"
	"gvisor.googlesource.com/gvisor/pkg/sentry/kernel"
	"gvisor.googlesource.com/gvisor/pkg/sentry/kernel/auth"
	"gvisor.googlesource.com/gvisor/pkg/waiter"
)

// New creates a new FileAsync.
func New() fs.FileAsync {
	return &FileAsync{}
}

// FileAsync sends signals when the registered file is ready for IO.
type FileAsync struct {
	mu        sync.Mutex
	e         waiter.Entry
	requester *auth.Credentials

	// Only one of the following is allowed to be non-nil.
	recipientPG *kernel.ProcessGroup
	recipientTG *kernel.ThreadGroup
	recipientT  *kernel.Task
}

// Callback sends a signal.
func (a *FileAsync) Callback(e *waiter.Entry) {
	a.mu.Lock()
	if a.e.Callback == nil {
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
	c := t.Credentials()
	// Logic from sigio_perm in fs/fcntl.c.
	if a.requester.EffectiveKUID == 0 ||
		a.requester.EffectiveKUID == c.SavedKUID ||
		a.requester.EffectiveKUID == c.RealKUID ||
		a.requester.RealKUID == c.SavedKUID ||
		a.requester.RealKUID == c.RealKUID {
		t.SendSignal(&arch.SignalInfo{
			Signo: int32(linux.SIGIO),
			// SEND_SIG_PRIV
			Code: arch.SignalInfoKernel,
		})
	}
	a.mu.Unlock()
}

// Register sets the file which will be monitored for IO events.
//
// The file must not be currently registered.
func (a *FileAsync) Register(w waiter.Waitable) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.e.Callback != nil {
		panic("registering already registered file")
	}

	a.e.Callback = a
	w.EventRegister(&a.e, waiter.EventIn|waiter.EventOut|waiter.EventErr|waiter.EventHUp)
}

// Unregister stops monitoring a file.
//
// The file must be currently registered.
func (a *FileAsync) Unregister(w waiter.Waitable) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.e.Callback == nil {
		panic("unregistering unregistered file")
	}

	w.EventUnregister(&a.e)
	a.e.Callback = nil
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
