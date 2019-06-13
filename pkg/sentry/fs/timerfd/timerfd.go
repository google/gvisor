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

// Package timerfd implements the semantics of Linux timerfd objects as
// described by timerfd_create(2).
package timerfd

import (
	"sync/atomic"

	"gvisor.dev/gvisor/pkg/sentry/context"
	"gvisor.dev/gvisor/pkg/sentry/fs"
	"gvisor.dev/gvisor/pkg/sentry/fs/anon"
	"gvisor.dev/gvisor/pkg/sentry/fs/fsutil"
	ktime "gvisor.dev/gvisor/pkg/sentry/kernel/time"
	"gvisor.dev/gvisor/pkg/sentry/usermem"
	"gvisor.dev/gvisor/pkg/syserror"
	"gvisor.dev/gvisor/pkg/waiter"
)

// TimerOperations implements fs.FileOperations for timerfds.
//
// +stateify savable
type TimerOperations struct {
	fsutil.FileZeroSeek             `state:"nosave"`
	fsutil.FileNotDirReaddir        `state:"nosave"`
	fsutil.FileNoFsync              `state:"nosave"`
	fsutil.FileNoIoctl              `state:"nosave"`
	fsutil.FileNoMMap               `state:"nosave"`
	fsutil.FileNoSplice             `state:"nosave"`
	fsutil.FileNoopFlush            `state:"nosave"`
	fsutil.FileUseInodeUnstableAttr `state:"nosave"`

	events waiter.Queue `state:"zerovalue"`
	timer  *ktime.Timer

	// val is the number of timer expirations since the last successful call to
	// Readv, Preadv, or SetTime. val is accessed using atomic memory
	// operations.
	val uint64
}

// NewFile returns a timerfd File that receives time from c.
func NewFile(ctx context.Context, c ktime.Clock) *fs.File {
	dirent := fs.NewDirent(anon.NewInode(ctx), "anon_inode:[timerfd]")
	// Release the initial dirent reference after NewFile takes a reference.
	defer dirent.DecRef()
	tops := &TimerOperations{}
	tops.timer = ktime.NewTimer(c, tops)
	// Timerfds reject writes, but the Write flag must be set in order to
	// ensure that our Writev/Pwritev methods actually get called to return
	// the correct errors.
	return fs.NewFile(ctx, dirent, fs.FileFlags{Read: true, Write: true}, tops)
}

// Release implements fs.FileOperations.Release.
func (t *TimerOperations) Release() {
	t.timer.Destroy()
}

// PauseTimer pauses the associated Timer.
func (t *TimerOperations) PauseTimer() {
	t.timer.Pause()
}

// ResumeTimer resumes the associated Timer.
func (t *TimerOperations) ResumeTimer() {
	t.timer.Resume()
}

// Clock returns the associated Timer's Clock.
func (t *TimerOperations) Clock() ktime.Clock {
	return t.timer.Clock()
}

// GetTime returns the associated Timer's setting and the time at which it was
// observed.
func (t *TimerOperations) GetTime() (ktime.Time, ktime.Setting) {
	return t.timer.Get()
}

// SetTime atomically changes the associated Timer's setting, resets the number
// of expirations to 0, and returns the previous setting and the time at which
// it was observed.
func (t *TimerOperations) SetTime(s ktime.Setting) (ktime.Time, ktime.Setting) {
	return t.timer.SwapAnd(s, func() { atomic.StoreUint64(&t.val, 0) })
}

// Readiness implements waiter.Waitable.Readiness.
func (t *TimerOperations) Readiness(mask waiter.EventMask) waiter.EventMask {
	var ready waiter.EventMask
	if atomic.LoadUint64(&t.val) != 0 {
		ready |= waiter.EventIn
	}
	return ready
}

// EventRegister implements waiter.Waitable.EventRegister.
func (t *TimerOperations) EventRegister(e *waiter.Entry, mask waiter.EventMask) {
	t.events.EventRegister(e, mask)
}

// EventUnregister implements waiter.Waitable.EventUnregister.
func (t *TimerOperations) EventUnregister(e *waiter.Entry) {
	t.events.EventUnregister(e)
}

// Read implements fs.FileOperations.Read.
func (t *TimerOperations) Read(ctx context.Context, file *fs.File, dst usermem.IOSequence, offset int64) (int64, error) {
	const sizeofUint64 = 8
	if dst.NumBytes() < sizeofUint64 {
		return 0, syserror.EINVAL
	}
	if val := atomic.SwapUint64(&t.val, 0); val != 0 {
		var buf [sizeofUint64]byte
		usermem.ByteOrder.PutUint64(buf[:], val)
		if _, err := dst.CopyOut(ctx, buf[:]); err != nil {
			// Linux does not undo consuming the number of expirations even if
			// writing to userspace fails.
			return 0, err
		}
		return sizeofUint64, nil
	}
	return 0, syserror.ErrWouldBlock
}

// Write implements fs.FileOperations.Write.
func (t *TimerOperations) Write(context.Context, *fs.File, usermem.IOSequence, int64) (int64, error) {
	return 0, syserror.EINVAL
}

// Notify implements ktime.TimerListener.Notify.
func (t *TimerOperations) Notify(exp uint64) {
	atomic.AddUint64(&t.val, exp)
	t.events.Notify(waiter.EventIn)
}

// Destroy implements ktime.TimerListener.Destroy.
func (t *TimerOperations) Destroy() {}
