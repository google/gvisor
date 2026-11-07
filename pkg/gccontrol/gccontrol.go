// Copyright 2026 The gVisor Authors.
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

// Package gccontrol controls temporary suspension of the Go garbage collector.
package gccontrol

import (
	"math"
	"runtime"
	"runtime/debug"
	"runtime/metrics"
	"time"

	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sync"
)

// NoMemoryLimit indicates to Suspend that no host memory limit applies.
const NoMemoryLimit uint64 = math.MaxUint64

// defaultMemoryLimit caps the Go runtime soft memory limit at 256 MiB for
// Suspend so unconstrained hosts still bound memory growth.
const defaultMemoryLimit uint64 = 256 << 20

const (
	// gcDisabled is passed to debug.SetGCPercent to disable periodic GC.
	gcDisabled = -1
	// queryMemoryLimit is passed to debug.SetMemoryLimit to read the
	// current limit without modifying it.
	queryMemoryLimit = -1
)

var mu sync.Mutex

// suspensionSession tracks the runtime GC settings shared across overlapping
// Suspend calls and any EndAfter grace deadline.
type suspensionSession struct {
	// refs is the number of active handles on this session that have
	// neither ended nor transitioned to the grace deadline via EndAfter.
	// +checklocks:mu
	refs int
	// prevPercent is the GOGC percentage to restore on resume.
	// +checklocks:mu
	prevPercent int
	// prevLimit is the memory limit to restore on resume.
	// +checklocks:mu
	prevLimit int64
	// hostLimit is the tightest host/cgroup soft memory limit requested in
	// this session.
	// +checklocks:mu
	hostLimit uint64
	// activeLimit is the soft memory limit currently set on the runtime.
	// +checklocks:mu
	activeLimit uint64
	// resumed reports whether GC has been resumed for this session.
	// +checklocks:mu
	resumed bool
	// deadline is the latest EndAfter expiration time, or zero if none.
	// +checklocks:mu
	deadline time.Time
	// timer fires onDeadline once deadline elapses.
	// +checklocks:mu
	timer *time.Timer
}

// +checklocks:mu
func (s *suspensionSession) setMemoryLimitLocked(limit uint64) {
	if limit == s.activeLimit {
		return
	}
	s.activeLimit = limit
	debug.SetMemoryLimit(int64(s.activeLimit))
}

// +checklocks:mu
func (s *suspensionSession) resumeGCLocked() {
	if s.resumed {
		return
	}
	s.resumed = true
	// Re-enable regular GC before lifting the memory limit so GC is never
	// left disabled with an unbounded limit.
	debug.SetGCPercent(s.prevPercent)
	debug.SetMemoryLimit(s.prevLimit)
}

// +checklocks:mu
func (s *suspensionSession) stopTimerLocked() {
	if s.timer != nil {
		s.timer.Stop()
		s.timer = nil
	}
	s.deadline = time.Time{}
}

// +checklocks:mu
func (s *suspensionSession) armTimerLocked() {
	d := max(time.Duration(0), time.Until(s.deadline))
	if s.timer == nil {
		s.timer = time.AfterFunc(d, s.onDeadline)
		return
	}
	s.timer.Reset(d)
}

// +checklocks:mu
func (s *suspensionSession) resumeEarlyLocked() {
	s.resumeGCLocked()
	if s.refs == 0 {
		s.stopTimerLocked()
		if current == s {
			current = nil
		}
	}
}

func (s *suspensionSession) onDeadline() {
	mu.Lock()
	defer mu.Unlock()
	if current != s || s.refs > 0 || s.deadline.IsZero() {
		return
	}
	if rem := time.Until(s.deadline); rem > 0 {
		if s.timer != nil {
			s.timer.Reset(rem)
		}
		return
	}
	s.stopTimerLocked()
	s.resumeGCLocked()
	current = nil
}

type gcState int

const (
	// stateIdle means no suspension session is active.
	stateIdle gcState = iota
	// stateSuspended means GC is currently suspended.
	stateSuspended
	// stateResumed means a session is still open, but GC resumed early.
	stateResumed
)

// current holds the active session, or nil when idle.
//
// +checklocks:mu
var current *suspensionSession

// +checklocks:mu
func currentStateLocked() gcState {
	switch {
	case current == nil:
		return stateIdle
	case current.resumed:
		return stateResumed
	default:
		return stateSuspended
	}
}

// resumeOnGC is registered as a GC cleanup callback on an unreachable
// allocation so that if GC runs while suspended (from reaching the soft memory
// limit, or any other reason), regular GC is resumed immediately.
func resumeOnGC(s *suspensionSession) {
	mu.Lock()
	defer mu.Unlock()
	if s.resumed {
		return
	}
	s.resumeEarlyLocked()
	log.Infof("Garbage collection ran while suspended; resuming it early")
}

// Suspension is a caller's handle to a suspensionSession.
type Suspension struct {
	// session is cleared on End.
	//
	// +checklocks:mu
	session *suspensionSession
	// inGrace is true once EndAfter has released this handle's active
	// reference onto session.deadline.
	//
	// +checklocks:mu
	inGrace bool
}

// hostMemoryLimit calculates the Go runtime soft memory limit imposed by
// totalMem after reserving untrackedMem.
func hostMemoryLimit(totalMem, untrackedMem uint64) uint64 {
	if totalMem == NoMemoryLimit {
		return math.MaxInt64
	}
	// Cap to half of the quota left after untracked memory so the Go
	// runtime collects and resumes normal GC before hitting host OOM.
	remaining := totalMem - min(totalMem, untrackedMem)
	return remaining / 2
}

// growthMemoryLimit returns used + max(used, minHeadroom), saturating at
// math.MaxInt64.
func growthMemoryLimit(used, minHeadroom uint64) uint64 {
	const maxLimit = uint64(math.MaxInt64)
	headroom := max(used, minHeadroom)
	if headroom >= maxLimit || used > maxLimit-headroom {
		return maxLimit
	}
	return used + headroom
}

// callerMemoryLimit returns the soft memory limit cap for a caller given the
// current Go runtime footprint.
func callerMemoryLimit(used, minHeadroom uint64, scaleWithUsed bool) uint64 {
	if !scaleWithUsed {
		return defaultMemoryLimit
	}
	return growthMemoryLimit(used, minHeadroom)
}

// hasHeadroom reports whether effectiveLimit leaves at least `used` bytes of
// free headroom so suspending GC is no tighter than GOGC=100 doubling.
func hasHeadroom(used, effectiveLimit uint64) bool {
	return effectiveLimit > 0 && used <= effectiveLimit && effectiveLimit-used >= used
}

// runtimeMetrics returns the Go runtime's current physical memory footprint in
// bytes, whether periodic GC is currently enabled, and whether reading
// succeeded.
func runtimeMetrics() (used uint64, gcEnabled bool, ok bool) {
	samples := [3]metrics.Sample{
		{Name: "/memory/classes/total:bytes"},
		{Name: "/memory/classes/heap/released:bytes"},
		{Name: "/gc/gogc:percent"},
	}
	metrics.Read(samples[:])
	if samples[0].Value.Kind() != metrics.KindUint64 ||
		samples[1].Value.Kind() != metrics.KindUint64 ||
		samples[2].Value.Kind() != metrics.KindUint64 {
		return 0, false, false
	}
	mapped := samples[0].Value.Uint64()
	released := samples[1].Value.Uint64()
	gcEnabled = int32(samples[2].Value.Uint64()) >= 0
	return mapped - min(mapped, released), gcEnabled, true
}

// +checklocks:mu
func startSuspensionLocked(prevLimit int64, hostLimit, effectiveLimit uint64) *suspensionSession {
	s := &suspensionSession{
		prevLimit:   prevLimit,
		hostLimit:   hostLimit,
		activeLimit: effectiveLimit,
	}
	// Apply the soft memory limit before disabling periodic GC.
	debug.SetMemoryLimit(int64(effectiveLimit))
	s.prevPercent = debug.SetGCPercent(gcDisabled)
	// Allocate an unreachable pointer-containing object after disabling GC
	// so resumeOnGC runs if GC triggers while suspended.
	runtime.AddCleanup(new(*byte), resumeOnGC, s)
	return s
}

// Suspend disables GC with a soft memory limit capped at 256 MiB (and half of
// the remaining host budget) until End is called. If totalMem is zero or
// insufficient headroom remains, Suspend returns nil (and resumes GC early if
// a session was suspended).
func Suspend(totalMem, untrackedMem uint64) *Suspension {
	return suspend(totalMem, untrackedMem, 0, false /* scaleWithUsed */)
}

// SuspendWithHeadroom disables GC like Suspend, scaling the soft memory limit
// to used + max(used, minHeadroom) (capped at half of the remaining host
// budget) until End is called.
func SuspendWithHeadroom(totalMem, untrackedMem, minHeadroom uint64) *Suspension {
	return suspend(totalMem, untrackedMem, minHeadroom, true /* scaleWithUsed */)
}

func suspend(totalMem, untrackedMem, minHeadroom uint64, scaleWithUsed bool) *Suspension {
	hostLimit := hostMemoryLimit(totalMem, untrackedMem)
	mu.Lock()
	defer mu.Unlock()
	switch currentStateLocked() {
	case stateIdle:
		if hostLimit == 0 {
			return nil
		}
		prevLimit := debug.SetMemoryLimit(queryMemoryLimit)
		if prevLimit <= 0 {
			return nil
		}
		// Leave caller settings untouched when periodic GC is already
		// disabled, and require at least `used` bytes of free headroom
		// below effectiveLimit to avoid triggering GC right away.
		used, gcEnabled, ok := runtimeMetrics()
		if !ok || !gcEnabled {
			return nil
		}
		effectiveLimit := min(uint64(prevLimit), hostLimit, callerMemoryLimit(used, minHeadroom, scaleWithUsed))
		if !hasHeadroom(used, effectiveLimit) {
			return nil
		}
		current = startSuspensionLocked(prevLimit, hostLimit, effectiveLimit)
	case stateSuspended:
		if hostLimit == 0 {
			current.resumeEarlyLocked()
			return nil
		}
		current.hostLimit = min(current.hostLimit, hostLimit)
		used, _, ok := runtimeMetrics()
		if !ok {
			current.resumeEarlyLocked()
			return nil
		}
		effectiveLimit := min(uint64(current.prevLimit), current.hostLimit, callerMemoryLimit(used, minHeadroom, scaleWithUsed))
		if current.refs > 0 {
			effectiveLimit = min(current.activeLimit, effectiveLimit)
		}
		if !hasHeadroom(used, effectiveLimit) {
			current.resumeEarlyLocked()
			return nil
		}
		current.setMemoryLimitLocked(effectiveLimit)
	case stateResumed:
		if hostLimit == 0 {
			return nil
		}
		// GC resumed early; track refs so MaybeFreeOSMemory is skipped
		// until End.
	}
	current.refs++
	return &Suspension{session: current}
}

// End closes `h` if it has not already. When no active handles remain on the
// session, any pending EndAfter deadline is cancelled and GC settings are
// restored.
func (h *Suspension) End() {
	if h == nil {
		return
	}
	mu.Lock()
	defer mu.Unlock()
	h.endLocked()
}

// EndAfter releases `h`'s active reference and extends the session's grace
// deadline to at least `time.Now().Add(d)`. When the deadline elapses with no
// active handles, GC settings are restored. If `h` is nil or already ended,
// EndAfter is a no-op.
func (h *Suspension) EndAfter(d time.Duration) {
	if h == nil {
		return
	}
	if d <= 0 {
		h.End()
		return
	}
	mu.Lock()
	defer mu.Unlock()
	s := h.session
	if s == nil {
		return
	}
	if !h.inGrace {
		h.inGrace = true
		s.refs--
		if s.refs < 0 {
			log.BugTracebackf("Negative suspension session refcount: %d", s.refs)
		}
	}
	if current != s || s.resumed {
		h.session = nil
		if s.refs <= 0 {
			s.stopTimerLocked()
			s.resumeGCLocked()
			if current == s {
				current = nil
			}
		}
		return
	}
	if exp := time.Now().Add(d); exp.After(s.deadline) {
		s.deadline = exp
	}
	s.armTimerLocked()
}

// +checklocks:mu
func (h *Suspension) endLocked() {
	s := h.session
	if s == nil {
		return
	}
	h.session = nil
	if !h.inGrace {
		s.refs--
		if s.refs < 0 {
			log.BugTracebackf("Negative suspension session refcount: %d", s.refs)
		}
	}
	if s.refs <= 0 {
		s.stopTimerLocked()
		s.resumeGCLocked()
		if current == s {
			current = nil
		}
	}
}

// MaybeFreeOSMemory forces a garbage collection and returns unused memory to
// the OS unless an active Suspension handle is open. Any pending EndAfter grace
// period is ended before collecting.
func MaybeFreeOSMemory() {
	mu.Lock()
	defer mu.Unlock()
	if current != nil {
		if current.refs > 0 {
			return
		}
		current.stopTimerLocked()
		current.resumeGCLocked()
		current = nil
	}
	debug.FreeOSMemory()
}
