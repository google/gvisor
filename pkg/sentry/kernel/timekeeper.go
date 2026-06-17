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
	"time"

	"gvisor.dev/gvisor/pkg/atomicbitops"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/ktime"
	sentrytime "gvisor.dev/gvisor/pkg/sentry/time"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/tcpip"
)

// Run states of the Timekeeper's updater goroutine, held atomically in
// Timekeeper.updaterState.
const (
	// updaterActive indicates that tasks are running, so the updater goroutine
	// refreshes the clock parameters periodically.
	updaterActive int32 = iota

	// updaterIdle indicates that no tasks are running; the updater goroutine
	// should park at its next opportunity. Set by markIdle.
	updaterIdle

	// updaterParked indicates that the updater goroutine has committed to
	// parking and stopped refreshing. Set by the goroutine; cleared back to
	// updaterActive by notifyActive, which refreshes on its behalf.
	updaterParked
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

	// stop is closed to tell the updater goroutine to exit. It is also selected
	// on while parked, so closing it wakes a parked goroutine.
	stop chan struct{} `state:"nosave"`

	// wg is used to indicate that the update goroutine has exited.
	wg sync.WaitGroup `state:"nosave"`

	// updaterState is the run state of the updater goroutine (one of
	// updaterActive, updaterIdle, updaterParked). All transitions are atomic,
	// which keeps the goroutine's "commit to park" race-free against
	// notifyActive's "is it parked" without a lock — so markIdle never blocks.
	updaterState atomicbitops.Int32 `state:"nosave"`

	// updateMu serializes a refresh with arming the timer for the next one, so
	// the VDSO parameter page (single writer) is never written twice at once.
	// notifyActive refreshes only while the goroutine is parked, having armed the
	// timer that wakes it a full interval later, so the goroutine's own refresh
	// normally comes well after. updateMu only matters if notifyActive is
	// descheduled between arming and refreshing past that interval, where it makes
	// the woken goroutine wait. markIdle does not take it, so it never blocks.
	updateMu sync.Mutex `state:"nosave"`

	// timer fires when the next periodic refresh is due, and is also how the
	// parked goroutine is woken: while parked it blocks in a select on timer.C
	// with the timer unarmed (so it never fires); notifyActive re-arms it, and
	// the goroutine wakes when it next fires.
	timer *time.Timer `state:"nosave"`
}

// NewTimekeeper returns a Timekeeper that is automatically kept up-to-date.
// NewTimekeeper does not take ownership of paramPage.
//
// SetClocks must be called on the returned Timekeeper before it is usable.
func NewTimekeeper() *Timekeeper {
	t := Timekeeper{}
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

	t.clocks = c

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

	if t.restored != nil {
		close(t.restored)
	}
}

// update samples the backing clocks and writes the new parameters to the VDSO
// parameter page.
//
// Preconditions: updateMu must be held (the VDSO parameter page has a single
// writer; see updateMu).
func (t *Timekeeper) update(params *VDSOParamPage) {
	// Call Update within a Write block to prevent the VDSO from using the old
	// params between Update and Write.
	if err := params.Write(func() vdsoParams {
		monotonicParams, monotonicOk, realtimeParams, realtimeOk := t.clocks.Update()

		var p vdsoParams
		if monotonicOk {
			p.monotonicReady = 1
			p.monotonicBaseCycles = int64(monotonicParams.BaseCycles)
			p.monotonicBaseRef = int64(monotonicParams.BaseRef) + t.monotonicOffset
			p.monotonicFrequency = monotonicParams.Frequency
		}
		if realtimeOk {
			p.realtimeReady = 1
			p.realtimeBaseCycles = int64(realtimeParams.BaseCycles)
			p.realtimeBaseRef = int64(realtimeParams.BaseRef)
			p.realtimeFrequency = realtimeParams.Frequency
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
	t.updaterState.Store(updaterActive)

	// Keep the clocks up to date.
	//
	// Note that the Go runtime uses host CLOCK_MONOTONIC to service the
	// timer, so it may run at a *slightly* different rate from the
	// application CLOCK_MONOTONIC. That is fine, as we only need to update
	// at approximately this rate.
	//
	// To avoid waking up the host periodically when nothing can read the
	// clock, the updater parks itself while no tasks are running (see
	// markIdle): while parked it leaves the timer unarmed, so the select below
	// blocks with no host timer pending. notifyActive re-arms the timer when a
	// task becomes runnable, which both wakes this select and schedules the next
	// tick, and refreshes the params synchronously so the resuming task never
	// observes stale data.
	t.timer = time.NewTimer(sentrytime.ApproxUpdateInterval)
	t.wg.Add(1)
	go func() { // S/R-SAFE: stopped during save.
		defer t.wg.Done()
		defer t.timer.Stop()
		for {
			// If our CAS fails, a task is running (state is active): arm the timer
			// for the next tick before refreshing, so the cadence is anchored to
			// now rather than pushed out by the refresh (or a preemption during
			// it). The first iteration makes the clocks ready ASAP.
			//
			// If the CAS succeeds, no task is running, so nothing can read the
			// params: we park by leaving the timer unarmed (it was drained by the
			// previous iteration's receive), and the select below blocks until
			// notifyActive re-arms it. No host timer is armed while parked.
			if !t.updaterState.CompareAndSwap(updaterIdle, updaterParked) {
				t.updateMu.Lock()
				t.timer.Reset(sentrytime.ApproxUpdateInterval)
				t.update(params)
				t.updateMu.Unlock()
			}

			// Wait for the next tick (or, if parked, until notifyActive arms the
			// timer), draining timer.C so the next park starts unarmed.
			select {
			case <-t.timer.C:
			case <-t.stop:
				return
			}
		}
	}()
}

// notifyActive ensures the clock parameters are up to date and wakes the
// updater goroutine if it is parked.
//
// It must be called when a task becomes runnable after the sentry has been
// idle, on the task goroutine and before the task can read the clock, so that
// the task never observes stale clock parameters (which may have drifted while
// idle, since updates were paused). params must be the same VDSOParamPage that
// was passed to SetClocks.
func (t *Timekeeper) notifyActive(params *VDSOParamPage) {
	// Mark the updater active and learn its previous state. The atomic swap is
	// race-free against the goroutine committing to park: either it set parked
	// before this swap (we observe updaterParked and refresh on its behalf), or
	// its CAS(idle -> parked) loses to this swap and it refreshes itself.
	if t.updaterState.Swap(updaterActive) != updaterParked {
		// The updater is still cycling, so the parameters are at most one update
		// interval old already — the same freshness the periodic updater provides
		// — and it will keep refreshing on its own. Nothing to do, and we avoid
		// an update on what may be a frequent wakeup path.
		return
	}

	// The updater was parked: updates were paused and the parameters may have
	// drifted. Under updateMu, arm the timer — which schedules the next tick and,
	// one interval out, wakes the parked goroutine — then refresh synchronously,
	// on this task goroutine, before it can read the clock. The goroutine wakes an
	// interval from now, so it normally won't contend for updateMu; the lock only
	// matters if we're descheduled here past that interval, when it serializes the
	// goroutine's refresh after ours rather than letting them write concurrently.
	t.updateMu.Lock()
	t.timer.Reset(sentrytime.ApproxUpdateInterval)
	t.update(params)
	t.updateMu.Unlock()
}

// markIdle indicates that no tasks are running, allowing the updater goroutine
// to park rather than continue updating clock parameters that nothing can read.
// The updater is reactivated by notifyActive.
func (t *Timekeeper) markIdle() {
	t.updaterState.CompareAndSwap(updaterActive, updaterIdle)
}

// stopUpdater stops the update goroutine, blocking until it exits.
//
// mu must be held.
func (t *Timekeeper) stopUpdater() {
	if t.stop == nil {
		// Updater not running.
		return
	}

	// Closing stop tells the goroutine to exit and wakes it if it is parked,
	// since the park and tick selects both wait on stop.
	close(t.stop)
	t.wg.Wait()
	t.stop = nil
}

// Destroy destroys the Timekeeper, freeing all associated resources.
func (t *Timekeeper) Destroy() {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.stopUpdater()
}

// PauseUpdates stops clock parameter updates. This should only be used when
// Tasks are not running and thus cannot access the clock.
func (t *Timekeeper) PauseUpdates() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.stopUpdater()
}

// ResumeUpdates restarts clock parameter updates stopped by PauseUpdates.
func (t *Timekeeper) ResumeUpdates(params *VDSOParamPage) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.startUpdater(params)
}

// GetTime returns the current time in nanoseconds.
func (t *Timekeeper) GetTime(c sentrytime.ClockID) (int64, error) {
	if t.clocks == nil {
		if t.restored == nil {
			panic("Timekeeper used before initialized with SetClocks")
		}
		<-t.restored
	}
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

// AfterFunc implements tcpip.Clock.
func (t *Timekeeper) AfterFunc(d time.Duration, f func()) tcpip.Timer {
	timer := &timekeeperTcpipTimer{
		clock: t.monotonicClock,
		fn:    f,
	}
	timer.Reset(d)
	return timer
}

// timekeeperTcpipTimer implements tcpip.Timer by wrapping a ktime.SampledTimer.
// tcpip.Timer does not define a Destroy method, so each timer expiration and
// each call to Timer.Stop() must release all resources by calling
// ktime.SampledTimer.Destroy().
type timekeeperTcpipTimer struct {
	// immutable
	clock *timekeeperClock
	fn    func()

	// mu protects t.
	mu timekeeperTcpipTimerMutex

	// t stores the latest running Timer. This is replaced whenever Reset is
	// called since Timer cannot be restarted once it has been Destroyed by Stop.
	//
	// This field is nil iff Stop has been called.
	t *ktime.SampledTimer

	// resets is the number of times Reset has been called. resets is written
	// with both mu and ktime.SampledTimer locks held, so it may be read with
	// either or both locks held.
	resets int
}

// Stop implements tcpip.Timer.Stop.
func (r *timekeeperTcpipTimer) Stop() bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.t == nil {
		return false
	}
	_, lastSetting := r.t.Set(ktime.Setting{}, nil)
	r.t.Destroy()
	r.t = nil
	return lastSetting.Enabled
}

// stopExpired is equivalent to Stop, but is called when the timer expires.
func (r *timekeeperTcpipTimer) stopExpired(reset int) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.t == nil || r.resets != reset {
		return
	}
	r.t.Destroy()
	r.t = nil
}

// Reset implements tcpip.Timer.Reset.
func (r *timekeeperTcpipTimer) Reset(d time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.t == nil {
		r.t = ktime.NewSampledTimer(r.clock, r)
	}
	r.t.Set(ktime.Setting{
		Enabled: true,
		Next:    r.clock.Now().Add(d),
	}, r.incResets)
}

func (r *timekeeperTcpipTimer) incResets() {
	r.resets++
}

// NotifyTimer implements ktime.Listener.NotifyTimer.
func (r *timekeeperTcpipTimer) NotifyTimer(exp uint64) {
	// Implementations of ktime.Listener.NotifyTimer() can't call Timer methods
	// due to lock ordering, so we must call r.t.Destroy() from another
	// goroutine. We also must call r.stopExpired() rather than r.Stop(), since
	// the latter might cancel an unrelated call to r.Reset() that happens
	// between now and when this goroutine runs.
	thisReset := r.resets
	go func() {
		r.stopExpired(thisReset)
		r.fn()
	}()
}
