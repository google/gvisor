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
	stdcontext "context"
	"maps"
	"slices"

	"gvisor.dev/gvisor/pkg/atomicbitops"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/ktime"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/usermem"
	"gvisor.dev/gvisor/pkg/waiter"
)

// RestoreRegistryKey identifies the receiving kernel's Registry during state
// loading. Each live file rejoins it regardless of how the file was reached.
type RestoreRegistryKey struct{}

// Registry tracks a kernel's live timerfds, including those referenced only by
// queued SCM_RIGHTS messages. Its zero value is ready for use.
type Registry struct {
	mu sync.Mutex
	// +checklocks:mu
	timers map[*ktime.SampledTimer]struct{}
}

// Timers returns the timers to pause or resume while tasks are stopped.
// SampledTimer permits both operations after a concurrent final Release.
func (r *Registry) Timers() []*ktime.SampledTimer {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Collect(maps.Keys(r.timers))
}

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
	timer  *ktime.SampledTimer

	// registry is set before the file is published and remains valid until
	// Release. afterLoad reconstructs this runtime index.
	registry *Registry `state:"nosave"`

	// clock is the clock that the timer fd was created with. timer runs on
	// clock, except when it is armed with a relative CLOCK_REALTIME time (see
	// SetTime). clock is immutable.
	clock ktime.SampledClock

	// val is the number of timer expirations since the last successful
	// call to PRead, or SetTime. val must be accessed using atomic memory
	// operations.
	val atomicbitops.Uint64
}

var _ vfs.FileDescriptionImpl = (*TimerFileDescription)(nil)
var _ ktime.Listener = (*TimerFileDescription)(nil)

// New returns a new timer fd.
func (r *Registry) New(ctx context.Context, vfsObj *vfs.VirtualFilesystem, clock ktime.SampledClock, flags uint32) (*vfs.FileDescription, error) {
	vd := vfsObj.NewAnonVirtualDentry("[timerfd]")
	defer vd.DecRef(ctx)
	tfd := &TimerFileDescription{clock: clock}
	if err := tfd.vfsfd.Init(tfd, flags, auth.CredentialsFromContext(ctx), vd.Mount(), vd.Dentry(), &vfs.FileDescriptionOptions{
		UseDentryMetadata: true,
		DenyPRead:         true,
		DenyPWrite:        true,
	}); err != nil {
		return nil, err
	}
	tfd.timer = ktime.NewSampledTimer(clock, tfd)
	tfd.register(r)
	return &tfd.vfsfd, nil
}

// Read implements vfs.FileDescriptionImpl.Read.
func (tfd *TimerFileDescription) Read(ctx context.Context, dst usermem.IOSequence, opts vfs.ReadOptions) (int64, error) {
	const sizeofUint64 = 8
	if dst.NumBytes() < sizeofUint64 {
		return 0, linuxerr.EINVAL
	}
	if val := tfd.val.Swap(0); val != 0 {
		var buf [sizeofUint64]byte
		hostarch.ByteOrder.PutUint64(buf[:], val)
		if _, err := dst.CopyOut(ctx, buf[:]); err != nil {
			// Linux does not undo consuming the number of
			// expirations even if writing to userspace fails.
			return 0, err
		}
		return sizeofUint64, nil
	}
	return 0, linuxerr.ErrWouldBlock
}

// Clock returns the Clock that the timer fd was created with.
func (tfd *TimerFileDescription) Clock() ktime.SampledClock {
	return tfd.clock
}

// GetTime returns the associated Timer's setting and the time at which it was
// observed.
func (tfd *TimerFileDescription) GetTime() (ktime.Time, ktime.Setting) {
	return tfd.timer.Get()
}

// SetTime atomically changes the associated Timer's setting, and the clock it
// runs on to c, resets the number of expirations to 0, and returns the
// previous setting and the time at which it was observed.
func (tfd *TimerFileDescription) SetTime(c ktime.SampledClock, s ktime.Setting) (ktime.Time, ktime.Setting) {
	return tfd.timer.SetWithClock(c, s, func() { tfd.val.Store(0) })
}

// Readiness implements waiter.Waitable.Readiness.
func (tfd *TimerFileDescription) Readiness(mask waiter.EventMask) waiter.EventMask {
	var ready waiter.EventMask
	if tfd.val.Load() != 0 {
		ready |= waiter.ReadableEvents
	}
	return ready
}

// EventRegister implements waiter.Waitable.EventRegister.
func (tfd *TimerFileDescription) EventRegister(e *waiter.Entry) error {
	tfd.events.EventRegister(e)
	return nil
}

// EventUnregister implements waiter.Waitable.EventUnregister.
func (tfd *TimerFileDescription) EventUnregister(e *waiter.Entry) {
	tfd.events.EventUnregister(e)
}

// Epollable implements FileDescriptionImpl.Epollable.
func (tfd *TimerFileDescription) Epollable() bool {
	return true
}

func (tfd *TimerFileDescription) register(r *Registry) {
	tfd.registry = r
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.timers == nil {
		r.timers = make(map[*ktime.SampledTimer]struct{})
	}
	r.timers[tfd.timer] = struct{}{}
}

func (tfd *TimerFileDescription) afterLoad(ctx stdcontext.Context) {
	// Older checkpoints may have missed a timerfd when pausing timers.
	tfd.timer.Pause()
	tfd.register(ctx.Value(RestoreRegistryKey{}).(*Registry))
}

// Release implements vfs.FileDescriptionImpl.Release.
func (tfd *TimerFileDescription) Release(context.Context) {
	tfd.timer.Destroy()
	r := tfd.registry
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.timers, tfd.timer)
}

// NotifyTimer implements ktime.TimerListener.NotifyTimer.
func (tfd *TimerFileDescription) NotifyTimer(exp uint64) {
	tfd.val.Add(exp)
	tfd.events.Notify(waiter.ReadableEvents)
}
