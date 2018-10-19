// Copyright 2018 Google LLC
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
	"sync"
	"time"

	"gvisor.googlesource.com/gvisor/pkg/log"
	ktime "gvisor.googlesource.com/gvisor/pkg/sentry/kernel/time"
	"gvisor.googlesource.com/gvisor/pkg/sentry/platform"
	sentrytime "gvisor.googlesource.com/gvisor/pkg/sentry/time"
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

	// bootTime is the realtime when the system "booted". i.e., when
	// SetClocks was called in the initial (not restored) run.
	bootTime ktime.Time

	// monotonicOffset is the offset to apply to the monotonic clock output
	// from clocks.
	//
	// It is set only once, by SetClocks.
	monotonicOffset int64 `state:"nosave"`

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

	// params manages the parameter page.
	params *VDSOParamPage

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
func NewTimekeeper(platform platform.Platform, paramPage platform.FileRange) (*Timekeeper, error) {
	return &Timekeeper{
		params: NewVDSOParamPage(platform, paramPage),
	}, nil
}

// SetClocks the backing clock source.
//
// SetClocks must be called before the Timekeeper is used, and it may not be
// called more than once, as changing the clock source without extra correction
// could cause time discontinuities.
//
// It must also be called after Load.
func (t *Timekeeper) SetClocks(c sentrytime.Clocks) {
	// Update the params, marking them "not ready", as we may need to
	// restart calibration on this new machine.
	if t.restored != nil {
		if err := t.params.Write(func() vdsoParams {
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
	// just making a best-effort attempt to to make it appear that the app
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
	t.startUpdater()

	if t.restored != nil {
		close(t.restored)
	}
}

// startUpdater starts an update goroutine that keeps the clocks updated.
//
// mu must be held.
func (t *Timekeeper) startUpdater() {
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
		for {
			// Start with an update immediately, so the clocks are
			// ready ASAP.

			// Call Update within a Write block to prevent the VDSO
			// from using the old params between Update and
			// Write.
			if err := t.params.Write(func() vdsoParams {
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

				log.Debugf("Updating VDSO parameters: %+v", p)

				return p
			}); err != nil {
				log.Warningf("Unable to update VDSO parameter page: %v", err)
			}

			select {
			case <-timer.C:
			case <-t.stop:
				t.wg.Done()
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
func (t *Timekeeper) ResumeUpdates() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.startUpdater()
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
	}
	return now, err
}

// BootTime returns the system boot real time.
func (t *Timekeeper) BootTime() ktime.Time {
	return t.bootTime
}

// timekeeperClock is a ktime.Clock that reads time from a
// kernel.Timekeeper-managed clock.
//
// +stateify savable
type timekeeperClock struct {
	tk *Timekeeper
	c  sentrytime.ClockID

	// Implements ktime.Clock.WallTimeUntil.
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
