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

	// stop is used to tell the update goroutine to exit.
	stop chan struct{} `state:"nosave"`

	// wg is used to indicate that the update goroutine has exited.
	wg sync.WaitGroup `state:"nosave"`
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

// startUpdater starts an update goroutine that keeps the clocks updated.
//
// mu must be held.
func (t *Timekeeper) startUpdater(params *VDSOParamPage) {
	if t.stop != nil {
		// Timekeeper already started
		return
	}
	t.stop = make(chan struct{})

	// Keep the clocks up to date.
	//
	// Note that the Go runtime uses host CLOCK_MONOTONIC to service the
	// timer, so it may run at a *slightly* different rate from the
	// application CLOCK_MONOTONIC. That is fine, as we only need to update
	// at approximately this rate.
	timer := time.NewTicker(sentrytime.ApproxUpdateInterval)
	t.wg.Add(1)
	go func() { // S/R-SAFE: stopped during save.
		defer t.wg.Done()
		for {
			// Start with an update immediately, so the clocks are
			// ready ASAP.

			// Call Update within a Write block to prevent the VDSO
			// from using the old params between Update and
			// Write.
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

			select {
			case <-timer.C:
			case <-t.stop:
				return
			}
		}
	}()
}

// stopUpdater stops the update goroutine, blocking until it exits.
//
// mu must be held.
func (t *Timekeeper) stopUpdater() {
	if t.stop == nil {
		// Updater not running.
		return
	}

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
