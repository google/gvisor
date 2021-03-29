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

// Package timerfd implements timer fds.
package timerfd

import (
	"sync/atomic"

	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/hostarch"
	ktime "gvisor.dev/gvisor/pkg/sentry/kernel/time"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/syserror"
	"gvisor.dev/gvisor/pkg/usermem"
	"gvisor.dev/gvisor/pkg/waiter"
)

// TimerFileDescription implements vfs.FileDescriptionImpl for timer fds. It also
// implements ktime.TimerListener.
//
// +stateify savable
type TimerFileDescription struct {
	vfsfd vfs.FileDescription
	vfs.FileDescriptionDefaultImpl
	vfs.DentryMetadataFileDescriptionImpl
	vfs.NoLockFD

	events waiter.Queue
	timer  *ktime.Timer

	// val is the number of timer expirations since the last successful
	// call to PRead, or SetTime. val must be accessed using atomic memory
	// operations.
	val uint64
}

var _ vfs.FileDescriptionImpl = (*TimerFileDescription)(nil)
var _ ktime.TimerListener = (*TimerFileDescription)(nil)

// New returns a new timer fd.
func New(ctx context.Context, vfsObj *vfs.VirtualFilesystem, clock ktime.Clock, flags uint32) (*vfs.FileDescription, error) {
	vd := vfsObj.NewAnonVirtualDentry("[timerfd]")
	defer vd.DecRef(ctx)
	tfd := &TimerFileDescription{}
	tfd.timer = ktime.NewTimer(clock, tfd)
	if err := tfd.vfsfd.Init(tfd, flags, vd.Mount(), vd.Dentry(), &vfs.FileDescriptionOptions{
		UseDentryMetadata: true,
		DenyPRead:         true,
		DenyPWrite:        true,
	}); err != nil {
		return nil, err
	}
	return &tfd.vfsfd, nil
}

// Read implements vfs.FileDescriptionImpl.Read.
func (tfd *TimerFileDescription) Read(ctx context.Context, dst usermem.IOSequence, opts vfs.ReadOptions) (int64, error) {
	const sizeofUint64 = 8
	if dst.NumBytes() < sizeofUint64 {
		return 0, syserror.EINVAL
	}
	if val := atomic.SwapUint64(&tfd.val, 0); val != 0 {
		var buf [sizeofUint64]byte
		hostarch.ByteOrder.PutUint64(buf[:], val)
		if _, err := dst.CopyOut(ctx, buf[:]); err != nil {
			// Linux does not undo consuming the number of
			// expirations even if writing to userspace fails.
			return 0, err
		}
		return sizeofUint64, nil
	}
	return 0, syserror.ErrWouldBlock
}

// Clock returns the timer fd's Clock.
func (tfd *TimerFileDescription) Clock() ktime.Clock {
	return tfd.timer.Clock()
}

// GetTime returns the associated Timer's setting and the time at which it was
// observed.
func (tfd *TimerFileDescription) GetTime() (ktime.Time, ktime.Setting) {
	return tfd.timer.Get()
}

// SetTime atomically changes the associated Timer's setting, resets the number
// of expirations to 0, and returns the previous setting and the time at which
// it was observed.
func (tfd *TimerFileDescription) SetTime(s ktime.Setting) (ktime.Time, ktime.Setting) {
	return tfd.timer.SwapAnd(s, func() { atomic.StoreUint64(&tfd.val, 0) })
}

// Readiness implements waiter.Waitable.Readiness.
func (tfd *TimerFileDescription) Readiness(mask waiter.EventMask) waiter.EventMask {
	var ready waiter.EventMask
	if atomic.LoadUint64(&tfd.val) != 0 {
		ready |= waiter.ReadableEvents
	}
	return ready
}

// EventRegister implements waiter.Waitable.EventRegister.
func (tfd *TimerFileDescription) EventRegister(e *waiter.Entry, mask waiter.EventMask) {
	tfd.events.EventRegister(e, mask)
}

// EventUnregister implements waiter.Waitable.EventUnregister.
func (tfd *TimerFileDescription) EventUnregister(e *waiter.Entry) {
	tfd.events.EventUnregister(e)
}

// PauseTimer pauses the associated Timer.
func (tfd *TimerFileDescription) PauseTimer() {
	tfd.timer.Pause()
}

// ResumeTimer resumes the associated Timer.
func (tfd *TimerFileDescription) ResumeTimer() {
	tfd.timer.Resume()
}

// Release implements vfs.FileDescriptionImpl.Release.
func (tfd *TimerFileDescription) Release(context.Context) {
	tfd.timer.Destroy()
}

// Notify implements ktime.TimerListener.Notify.
func (tfd *TimerFileDescription) Notify(exp uint64, setting ktime.Setting) (ktime.Setting, bool) {
	atomic.AddUint64(&tfd.val, exp)
	tfd.events.Notify(waiter.ReadableEvents)
	return ktime.Setting{}, false
}

// Destroy implements ktime.TimerListener.Destroy.
func (tfd *TimerFileDescription) Destroy() {}
