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

package kernel

import (
	"fmt"
	"math"
	"time"

	"gvisor.dev/gvisor/pkg/atomicbitops"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/ktime"
	sentrytime "gvisor.dev/gvisor/pkg/sentry/time"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/tcpip"
)

// Possible values of Timekeeper.updaterState
const (
	// manually stopped
	updaterStopped int32 = iota

	// timer not armed due to being idle for a whole interval
	updaterParked

	// set when timer triggers if no tasks are running; any task running
	// or internal timekeeper usage transitions back to updaterActive
	updaterIdle

	updaterActive
)

// Timekeeper manages all of the kernel clocks.
//
// +stateify savable
type Timekeeper struct {
	// clocks are the clock sources.
	//
	// These are not saved directly, as the new machine's clock may behave
	// differently.
	//
	// It is set only once, by SetClocks.
	clocks sentrytime.Clocks `state:"nosave"`

	// realtimeClock is a ktime.Clock based on timekeeper's Realtime.
	realtimeClock *timekeeperClock

	// monotonicClock is a ktime.Clock based on timekeeper's Monotonic.
	monotonicClock *timekeeperClock

	// monotonicRawClock is a ktime.Clock based on timekeeper's MonotonicRaw.
	// It is non-nil only when the clock source tracks a distinct
	// CLOCK_MONOTONIC_RAW; otherwise CLOCK_MONOTONIC_RAW aliases
	// CLOCK_MONOTONIC. It is derived by SetClocks, anew on restore.
	monotonicRawClock *timekeeperClock `state:"nosave"`

	// bootTime is the realtime when the system "booted". i.e., when
	// SetClocks was called in the initial (not restored) run.
	bootTime ktime.Time

	// monotonicOffset is the offset to apply to the monotonic clock output
	// from clocks.
	//
	// It is set only once, by SetClocks.
	monotonicOffset int64 `state:"nosave"`

	// monotonicLowerBound is the lowerBound for monotonic time.
	monotonicLowerBound atomicbitops.Int64 `state:"nosave"`

	// restored, if non-nil, indicates that this Timekeeper was restored
	// from a state file. The clocks are not set until restored is closed.
	restored chan struct{} `state:"nosave"`

	// saveMonotonic is the (offset) value of the monotonic clock at the
	// time of save.
	//
	// It is only valid if restored is non-nil.
	//
	// It is only used in SetClocks after restore to compute the new
	// monotonicOffset.
	saveMonotonic int64

	// saveRealtime is the value of the realtime clock at the time of save.
	//
	// It is only valid if restored is non-nil.
	//
	// It is only used in SetClocks after restore to compute the new
	// monotonicOffset.
	saveRealtime int64

	// mu protects destruction with stop and wg.
	mu sync.Mutex `state:"nosave"`

	// stop is used to tell the update goroutine to exit.
	stop chan struct{} `state:"nosave"`

	// wg is used to indicate that the update goroutine has exited.
	wg sync.WaitGroup `state:"nosave"`

	// atomic enum with updater* values
	//
	// the goroutine moves it active->idle->parked (under updateMu)
	// GetTime or 0->1 tasks moves to active if not stopped (lockless)
	// startUpdater/stopUpdater move in/out of stopped (under updateMu)
	updaterState atomicbitops.Int32 `state:"nosave"`

	// (runningTasks > 0 ? 1 : 0) + number_of_tasks_running_GetTime
	refs atomicbitops.Int64 `state:"nosave"`

	// guards updates of the vDSO parameter page and of updaterState
	// except for raising updaterState to active on usage
	updateMu sync.Mutex `state:"nosave"`

	// timer to periodically update the time calibration
	timer *time.Timer `state:"nosave"`

	// vDSO parameter page kept updated by the Timekeeper mechanism
	params *VDSOParamPage `state:"nosave"`

	// pausableClock for AfterFunc callbacks.
	pausableClock *ktime.SyntheticClock `state:"nosave"`

	// afterFuncSchedulerWakeCh wakes the AfterFunc scheduler when
	// new timers are added.
	afterFuncSchedulerWakeCh chan struct{} `state:"nosave"`

	// afterFuncSchedulerCancel stops the AfterFunc scheduler and
	// waits for the callbacks to exit.
	// +checklocks:mu
	afterFuncSchedulerCancel func() `state:"nosave"`

	// activeAfterFuncs tracks running AfterFunc callbacks.
	activeAfterFuncs sync.WaitGroup `state:"nosave"`

	// afterFuncQueueMu protects afterFuncQueue.
	afterFuncQueueMu sync.Mutex `state:"nosave"`

	// afterFuncQueue holds expired AfterFunc timers that have not
	// yet been dispatched.
	//
	// +checklocks:afterFuncQueueMu
	afterFuncQueue []func() `state:"nosave"`

	// afterFuncSchedulerTarget is the earliest time that the AfterFunc
	// scheduler needs to wake and rescan.
	afterFuncSchedulerTarget atomicbitops.Int64 `state:"nosave"`
}

// NewTimekeeper returns a Timekeeper that is automatically kept up-to-date.
// NewTimekeeper does not take ownership of paramPage.
//
// SetClocks must be called on the returned Timekeeper before it is usable.
func NewTimekeeper() *Timekeeper {
	t := Timekeeper{}
	t.pausableClock = &ktime.SyntheticClock{}
	t.afterFuncSchedulerWakeCh = make(chan struct{}, 1)
	t.realtimeClock = &timekeeperClock{tk: &t, c: sentrytime.Realtime}
	t.monotonicClock = &timekeeperClock{tk: &t, c: sentrytime.Monotonic}
	return &t
}

// SetClocks the backing clock source.
//
// SetClocks must be called before the Timekeeper is used, and it may not be
// called more than once, as changing the clock source without extra correction
// could cause time discontinuities.
//
// It must also be called after Load.
func (t *Timekeeper) SetClocks(c sentrytime.Clocks, params *VDSOParamPage) {
	// Update the params, marking them "not ready", as we may need to
	// restart calibration on this new machine.
	if t.restored != nil {
		if err := params.Write(func() vdsoParams {
			return vdsoParams{}
		}); err != nil {
			panic("unable to reset VDSO params: " + err.Error())
		}
	}

	if t.clocks != nil {
		panic("SetClocks called on previously-initialized Timekeeper")
	}

	if t.pausableClock == nil {
		t.pausableClock = &ktime.SyntheticClock{}
	}
	if t.afterFuncSchedulerWakeCh == nil {
		t.afterFuncSchedulerWakeCh = make(chan struct{}, 1)
	}

	t.clocks = c

	// Serve CLOCK_MONOTONIC_RAW as a distinct clock iff the clock source
	// tracks it (see NewCalibratedClocks). Deriving this from the source keeps
	// boot and restore coherent: a restored sandbox follows its current
	// configuration, not the checkpointed one.
	if c.MonotonicRawEnabled() {
		t.monotonicRawClock = &timekeeperClock{tk: t, c: sentrytime.MonotonicRaw}
	}

	// Compute the offset of the monotonic clock from the base Clocks.
	//
	// In a fresh (not restored) sentry, monotonic time starts at zero.
	//
	// In a restored sentry, monotonic time jumps forward by approximately
	// the same amount as real time. There are no guarantees here, we are
	// just making a best-effort attempt to make it appear that the app
	// was simply not scheduled for a long period, rather than that the
	// real time clock was changed.
	//
	// If real time went backwards, it remains the same.
	wantMonotonic := int64(0)

	nowMonotonic, err := t.clocks.GetTime(sentrytime.Monotonic)
	if err != nil {
		panic("Unable to get current monotonic time: " + err.Error())
	}

	nowRealtime, err := t.clocks.GetTime(sentrytime.Realtime)
	if err != nil {
		panic("Unable to get current realtime: " + err.Error())
	}

	if t.restored != nil {
		wantMonotonic = t.saveMonotonic
		elapsed := nowRealtime - t.saveRealtime
		if elapsed > 0 {
			wantMonotonic += elapsed
		}
	}

	t.monotonicOffset = wantMonotonic - nowMonotonic

	if t.restored == nil {
		// Hold on to the initial "boot" time.
		t.bootTime = ktime.FromNanoseconds(nowRealtime)
	}

	t.mu.Lock()
	defer t.mu.Unlock()
	t.startUpdater(params)

	// Initialize the pausable clock with the current monotonic time and
	// start the background AfterFunc scheduler goroutine.
	nsec, err := t.GetTime(sentrytime.Monotonic)
	if err != nil {
		panic("Unable to get current monotonic time: " + err.Error())
	}
	t.pausableClock.Store(ktime.FromNanoseconds(nsec))
	t.startAfterFuncSchedulerLocked()

	if t.restored != nil {
		close(t.restored)
	}
}

// update samples the backing clocks and writes the new parameters to the VDSO
// parameter page.
//
// Preconditions: updateMu must be held
func (t *Timekeeper) update(parked bool) {
	// Call Update within a Write block to prevent the VDSO from using the old
	// params between Update and Write.
	if err := t.params.Write(func() vdsoParams {
		res := t.clocks.Update(parked)

		var p vdsoParams
		if res.MonotonicOk {
			p.monotonicReady = 1
			p.monotonicBaseCycles = int64(res.Monotonic.BaseCycles)
			p.monotonicBaseRef = int64(res.Monotonic.BaseRef) + t.monotonicOffset
			p.monotonicFrequency = res.Monotonic.Frequency
		}
		if res.RealtimeOk {
			p.realtimeReady = 1
			p.realtimeBaseCycles = int64(res.Realtime.BaseCycles)
			p.realtimeBaseRef = int64(res.Realtime.BaseRef)
			p.realtimeFrequency = res.Realtime.Frequency
		}
		if t.monotonicRawClock == nil {
			p.monotonicRawAlias = 1
		} else if res.MonotonicRawOk {
			// Raw tracks absolute host CLOCK_MONOTONIC_RAW, so unlike
			// monotonic its base ref is published without monotonicOffset.
			p.monotonicRawReady = 1
			p.monotonicRawBaseCycles = int64(res.MonotonicRaw.BaseCycles)
			p.monotonicRawBaseRef = int64(res.MonotonicRaw.BaseRef)
			p.monotonicRawFrequency = res.MonotonicRaw.Frequency
		}
		return p
	}); err != nil {
		log.Warningf("Unable to update VDSO parameter page: %v", err)
	}
}

// startUpdater starts an update goroutine that keeps the clocks updated.
//
// mu must be held.
func (t *Timekeeper) startUpdater(params *VDSOParamPage) {
	if t.stop != nil {
		// Timekeeper already started
		return
	}
	t.stop = make(chan struct{})
	t.params = params

	// Keep the clocks up to date.
	//
	// Note that the Go runtime uses host CLOCK_MONOTONIC to service the
	// timer, so it may run at a *slightly* different rate from the
	// application CLOCK_MONOTONIC. That is fine, as we only need to update
	// at approximately this rate.
	t.timer = time.NewTimer(sentrytime.ApproxUpdateInterval)
	t.timer.Stop()

	t.updateMu.Lock()
	// store-then-load to synchronize with addRef
	t.updaterState.Store(updaterParked)
	if t.refs.Load() != 0 {
		t.timer.Reset(sentrytime.ApproxUpdateInterval)
		t.update(true)
		t.updaterState.Store(updaterActive)
	}
	t.updateMu.Unlock()

	t.wg.Add(1)
	go func() { // S/R-SAFE: stopped during save.
		defer t.wg.Done()
		defer t.timer.Stop()
		for {
			// wait until next tick or if parked until addRef is called
			select {
			case <-t.timer.C:
			case <-t.stop:
				return
			}

			t.updateMu.Lock()

			switch t.updaterState.Load() {
			case updaterStopped:
				t.updateMu.Unlock()
				return

			case updaterActive:
				// store-then-load to synchronize with addRef
				t.updaterState.Store(updaterIdle)
				if t.refs.Load() != 0 {
					t.updaterState.Store(updaterActive)
				}

			case updaterIdle:
				// no Timekeeper usage for a whole interval: park
				// store-then-load to synchronize with addRef
				t.updaterState.Store(updaterParked)
				if t.refs.Load() != 0 {
					t.updaterState.Store(updaterActive)
				} else {
					t.updateMu.Unlock()
					continue
				}
			}

			t.timer.Reset(sentrytime.ApproxUpdateInterval)
			t.update(false)
			t.updateMu.Unlock()
		}
	}()
}

// add a reference to the Timekeeper: as long as there are references,
// it doesn't park. Call release() to release.
func (t *Timekeeper) addRef() {
	// store-then-load to synchronize with the goroutine
	t.refs.Add(1)
	switch t.updaterState.Load() {
	case updaterActive:
	case updaterIdle:
		// this is enough because the goroutine will
		// itself recheck refs after parking
		t.updaterState.CompareAndSwap(updaterIdle, updaterActive)
	case updaterParked:
		t.updateMu.Lock()
		cur := t.updaterState.Load()
		if cur == updaterParked {
			t.timer.Reset(sentrytime.ApproxUpdateInterval)
			t.update(true)
		}
		if cur != updaterStopped {
			t.updaterState.Store(updaterActive)
		}
		t.updateMu.Unlock()
	case updaterStopped:
	}
}

// release drops a reference taken by addRef; when refs are 0 the timekeeper can park
func (t *Timekeeper) release() {
	r := t.refs.Add(-1)
	if r < 0 {
		panic("Timekeeper.release called with no reference held")
	}
}

// stopUpdater stops the update goroutine, blocking until it exits.
//
// mu must be held.
func (t *Timekeeper) stopUpdater() {
	if t.stop == nil {
		// Updater not running.
		return
	}

	// lock to ensure it can't be taken out of stopped by non-startUpdater code
	t.updateMu.Lock()
	t.updaterState.Store(updaterStopped)
	t.updateMu.Unlock()

	// this wakes up the goroutine
	close(t.stop)
	t.wg.Wait()
	t.stop = nil
	t.timer = nil
	t.params = nil
}

// Destroy destroys the Timekeeper, freeing all associated resources.
func (t *Timekeeper) Destroy() {
	t.mu.Lock()
	t.stopUpdater()
	t.stopAfterFuncSchedulerLocked()
	t.mu.Unlock()

	t.activeAfterFuncs.Wait()
}

// Pause stops both clock updates and the AfterFunc scheduler, and waits for any
// active AfterFunc callbacks to finish.
func (t *Timekeeper) Pause() {
	t.mu.Lock()
	t.stopUpdater()
	t.stopAfterFuncSchedulerLocked()
	t.mu.Unlock()

	t.activeAfterFuncs.Wait()
}

// Resume restarts clock parameter updates and the AfterFunc scheduler.
func (t *Timekeeper) Resume(params *VDSOParamPage) {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.startUpdater(params)
	// Resynchronize the pausable clock with the current monotonic time and
	// restart the background AfterFunc scheduler goroutine.
	nsec, err := t.GetTime(sentrytime.Monotonic)
	if err != nil {
		panic(fmt.Sprintf("timekeeper.GetTime(sentrytime.Monotonic): %v", err))
	}
	t.pausableClock.Store(ktime.FromNanoseconds(nsec))
	t.startAfterFuncSchedulerLocked()
}

// GetTime returns the current time in nanoseconds.
func (t *Timekeeper) GetTime(c sentrytime.ClockID) (int64, error) {
	if t.clocks == nil {
		if t.restored == nil {
			panic("Timekeeper used before initialized with SetClocks")
		}
		<-t.restored
	}
	if c == sentrytime.MonotonicRaw && t.monotonicRawClock == nil {
		c = sentrytime.Monotonic
	}

	// update the calibration if needed and keep the timekeeper calibrated
	// during the read
	t.addRef()
	defer t.release()

	now, err := t.clocks.GetTime(c)
	if err == nil && c == sentrytime.Monotonic {
		now += t.monotonicOffset
		for {
			// It's possible that the clock is shaky. This may be due to
			// platform issues, e.g. the KVM platform relies on the guest
			// TSC and host TSC, which may not be perfectly in sync. To
			// work around this issue, ensure that the monotonic time is
			// always bounded by the last time read.
			oldLowerBound := t.monotonicLowerBound.Load()
			if now < oldLowerBound {
				now = oldLowerBound
				break
			}
			if t.monotonicLowerBound.CompareAndSwap(oldLowerBound, now) {
				break
			}
		}
	}
	return now, err
}

// BootTime returns the system boot real time.
func (t *Timekeeper) BootTime() ktime.Time {
	return t.bootTime
}

// timekeeperClock is a ktime.SampledClock that reads time from a
// kernel.Timekeeper-managed clock.
//
// +stateify savable
type timekeeperClock struct {
	tk *Timekeeper
	c  sentrytime.ClockID

	// Implements ktime.SampledClock.WallTimeUntil.
	ktime.WallRateClock `state:"nosave"`

	// Implements waiter.Waitable. (We have no ability to detect
	// discontinuities from external changes to CLOCK_REALTIME).
	ktime.NoClockEvents `state:"nosave"`
}

// Now implements ktime.Clock.Now.
func (tc *timekeeperClock) Now() ktime.Time {
	now, err := tc.tk.GetTime(tc.c)
	if err != nil {
		panic(fmt.Sprintf("timekeeperClock(ClockID=%v)).Now: %v", tc.c, err))
	}
	return ktime.FromNanoseconds(now)
}

// NewTimer implements ktime.Clock.NewTimer.
func (tc *timekeeperClock) NewTimer(l ktime.Listener) ktime.Timer {
	return ktime.NewSampledTimer(tc, l)
}

var _ tcpip.Clock = (*Timekeeper)(nil)

// Now implements tcpip.Clock.
func (t *Timekeeper) Now() time.Time {
	nsec, err := t.GetTime(sentrytime.Realtime)
	if err != nil {
		panic("timekeeper.GetTime(sentrytime.Realtime): " + err.Error())
	}
	return time.Unix(0, nsec)
}

// NowMonotonic implements tcpip.Clock.
func (t *Timekeeper) NowMonotonic() tcpip.MonotonicTime {
	nsec, err := t.GetTime(sentrytime.Monotonic)
	if err != nil {
		panic("timekeeper.GetTime(sentrytime.Monotonic): " + err.Error())
	}
	var mt tcpip.MonotonicTime
	return mt.Add(time.Duration(nsec) * time.Nanosecond)
}

// startAfterFuncSchedulerLocked starts the scheduler.
//
// +checklocks:t.mu
func (t *Timekeeper) startAfterFuncSchedulerLocked() {
	if t.afterFuncSchedulerCancel != nil {
		return
	}

	// stop signals the scheduler to exit.
	stop := make(chan struct{})
	// done is closed when the scheduler exits.
	done := make(chan struct{})
	t.afterFuncSchedulerCancel = func() {
		close(stop)
		<-done
	}
	go func() {
		defer close(done)
		t.runAfterFuncScheduler(stop)
	}()
}

// runAfterFuncScheduler updates pausableClock to trigger timers that have expired.
func (t *Timekeeper) runAfterFuncScheduler(stop <-chan struct{}) {
	// Initialize event timer.
	eventTimer := time.NewTimer(math.MaxInt64)
	eventTimer.Stop()
	defer eventTimer.Stop()

	for {
		// Reset the target time to the maximum value.
		t.afterFuncSchedulerTarget.Store(math.MaxInt64)

		// Set the current time of the pausable clock.
		nsec, err := t.GetTime(sentrytime.Monotonic)
		if err != nil {
			panic(fmt.Sprintf("timekeeper.GetTime(sentrytime.Monotonic), err: %v", err))
		}
		t.pausableClock.Store(ktime.FromNanoseconds(nsec))

		// Launch all the expired AfterFuncs.
		t.dispatchAfterFuncs()

		// Find the next timer expiration and set the event timer.
		var eventChan <-chan time.Time
		target := int64(math.MaxInt64)
		if nextExp, ok := t.pausableClock.NextExpiration(); ok {
			now := ktime.FromNanoseconds(nsec)
			var wait time.Duration
			if nextExp.After(now) {
				wait = nextExp.Sub(now)
			}
			eventTimer.Reset(wait)
			eventChan = eventTimer.C
			target = nextExp.Nanoseconds()
		}
		t.afterFuncSchedulerTarget.Store(target)

		// Wait for the next timer expiration or a stop signal.
		select {
		case <-stop:
			return
		case <-eventChan:
		case <-t.afterFuncSchedulerWakeCh:
			// Cancel the host timer if it was set.
			if eventChan != nil && !eventTimer.Stop() {
				// Drain the timer channel to avoid stale timers.
				select {
				case <-eventTimer.C:
				default:
				}
			}
		}
	}
}

// dispatchAfterFuncs starts a goroutine for each queued AfterFunc.
func (t *Timekeeper) dispatchAfterFuncs() {
	t.afterFuncQueueMu.Lock()
	fns := t.afterFuncQueue
	t.afterFuncQueue = nil
	t.afterFuncQueueMu.Unlock()
	for _, fn := range fns {
		t.activeAfterFuncs.Add(1)
		go func() {
			defer t.activeAfterFuncs.Done()
			fn()
		}()
	}
}

// stopAfterFuncSchedulerLocked stops the AfterFunc scheduler goroutine and waits for it to exit.
//
// +checklocks:t.mu
func (t *Timekeeper) stopAfterFuncSchedulerLocked() {
	if t.afterFuncSchedulerCancel != nil {
		t.afterFuncSchedulerCancel()
		t.afterFuncSchedulerCancel = nil
	}
}

// AfterFunc implements tcpip.Clock.
func (t *Timekeeper) AfterFunc(d time.Duration, f func()) tcpip.Timer {
	listener := &timekeeperListener{
		tk: t,
		fn: f,
	}
	timer := &timekeeperTimer{
		tk: t,
	}
	timer.Init(t.pausableClock, listener)
	timer.Reset(d)
	return timer
}

// timekeeperListener implements ktime.Listener to execute timer callbacks.
type timekeeperListener struct {
	tk *Timekeeper
	fn func()
}

// NotifyTimer implements ktime.Listener.NotifyTimer.
func (l *timekeeperListener) NotifyTimer(exp uint64) {
	if exp == 0 {
		log.BugTracebackfOnce("timekeeperListener.NotifyTimer called with exp == 0")
		return
	}
	tk := l.tk
	tk.afterFuncQueueMu.Lock()
	tk.afterFuncQueue = append(tk.afterFuncQueue, l.fn)
	tk.afterFuncQueueMu.Unlock()
	select {
	case tk.afterFuncSchedulerWakeCh <- struct{}{}:
	default:
	}
}

// timekeeperTimer implements tcpip.Timer to manage timer state.
type timekeeperTimer struct {
	ktime.SyntheticTimer
	tk *Timekeeper
}

// Stop implements tcpip.Timer.Stop.
// It cancels the timer and returns true if the timer was active.
func (timer *timekeeperTimer) Stop() bool {
	_, lastSetting := timer.Set(ktime.Setting{}, nil)
	return lastSetting.Enabled
}

// Reset implements tcpip.Timer.Reset.
func (timer *timekeeperTimer) Reset(d time.Duration) {
	nsec, err := timer.tk.GetTime(sentrytime.Monotonic)
	if err != nil {
		panic(fmt.Sprintf("timekeeperTimer.Reset: GetTime(Monotonic): %v", err))
	}
	next := ktime.FromNanoseconds(nsec).Add(d)
	if d > 0 {
		now := timer.tk.pausableClock.Now()
		if !next.After(now) {
			log.BugTracebackfOnce("timekeeperTimer.Reset(%v): deadline %v <= pausableClock %v (monotonic time went backwards)", d, next, now)
		}
	}
	timer.Set(ktime.Setting{
		Enabled: true,
		Next:    next,
	}, nil)
	// Wake the AfterFunc scheduler if the new deadline is earlier than the
	// scheduler's current wakeup target.
	if next.Nanoseconds() < timer.tk.afterFuncSchedulerTarget.Load() {
		select {
		case timer.tk.afterFuncSchedulerWakeCh <- struct{}{}:
		default:
		}
	}
}
