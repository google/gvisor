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

	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sync"
)

// NoMemoryLimit indicates to Suspend that no host memory limit applies.
const NoMemoryLimit uint64 = math.MaxUint64

// maxMemoryLimit caps the Go runtime soft memory limit at 1 GiB while GC is
// suspended so unconstrained hosts still bound memory growth.
const maxMemoryLimit uint64 = 1 << 30

var mu sync.Mutex

// suspensionSession tracks the runtime GC settings shared across overlapping
// Suspend calls; for example, when a checkpoint starts while the post-boot
// startup suspension is still active.
type suspensionSession struct {
	// refs is the number of open handles sharing this session.
	// +checklocks:mu
	refs int
	// prevPercent is the GOGC percentage to restore on resume.
	// +checklocks:mu
	prevPercent int
	// prevLimit is the memory limit to restore on resume.
	// +checklocks:mu
	prevLimit int64
	// minLimit is the tightest soft memory limit requested in this session.
	// +checklocks:mu
	minLimit uint64
	// resumed reports whether GC has been resumed for this session.
	// +checklocks:mu
	resumed bool
}

// +checklocks:mu
func (s *suspensionSession) lowerMemoryLimitLocked(limit uint64) {
	if limit >= s.minLimit {
		return
	}
	s.minLimit = limit
	debug.SetMemoryLimit(int64(s.minLimit))
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
	s.resumeGCLocked()
	log.Infof("Garbage collection ran while suspended; resuming it early")
}

// Suspension is a caller's handle to a suspensionSession.
type Suspension struct {
	// session is cleared on End.
	//
	// +checklocks:mu
	session *suspensionSession
}

// memoryLimit calculates a soft memory limit based on
// `totalMem`: host memory limit.
// `untrackedMem`: memory untracked by the Go runtime.
func memoryLimit(totalMem, untrackedMem uint64) uint64 {
	// Cap to half of the quota left after untracked memory so the Go
	// runtime collects and resumes normal GC before hitting host OOM.
	remaining := totalMem - min(totalMem, untrackedMem)
	return min(maxMemoryLimit, remaining/2)
}

// memoryUsed returns the Go runtime's current physical memory footprint in
// bytes.
func memoryUsed() (uint64, bool) {
	samples := [2]metrics.Sample{
		{Name: "/memory/classes/total:bytes"},
		{Name: "/memory/classes/heap/released:bytes"},
	}
	metrics.Read(samples[:])
	if samples[0].Value.Kind() != metrics.KindUint64 ||
		samples[1].Value.Kind() != metrics.KindUint64 {
		return 0, false
	}
	mapped := samples[0].Value.Uint64()
	released := samples[1].Value.Uint64()
	return mapped - min(mapped, released), true
}

// +checklocks:mu
func startSuspensionLocked(prevLimit int64, effectiveLimit uint64) *suspensionSession {
	s := &suspensionSession{
		prevLimit: prevLimit,
		minLimit:  effectiveLimit,
	}
	// Apply the soft memory limit before disabling periodic GC.
	debug.SetMemoryLimit(int64(effectiveLimit))
	s.prevPercent = debug.SetGCPercent(-1 /* percent */)
	// Allocate an unreachable pointer-containing object after disabling GC
	// so resumeOnGC runs if GC triggers while suspended.
	runtime.AddCleanup(new(*byte), resumeOnGC, s)
	return s
}

// Suspend disables GC with a soft memory limit until End is called.
// Returns nil if insufficient headroom remains.
func Suspend(totalMem, untrackedMem uint64) *Suspension {
	limit := memoryLimit(totalMem, untrackedMem)
	mu.Lock()
	defer mu.Unlock()
	switch currentStateLocked() {
	case stateIdle:
		if limit == 0 {
			return nil
		}
		// Get current limit.
		prevLimit := debug.SetMemoryLimit(-1 /* limit */)
		if prevLimit <= 0 {
			return nil
		}
		effectiveLimit := min(uint64(prevLimit), limit)
		// Require at least half of effectiveLimit to be free to avoid
		// triggering GC right after suspending.
		if used, ok := memoryUsed(); !ok || used >= effectiveLimit/2 {
			return nil
		}
		current = startSuspensionLocked(prevLimit, effectiveLimit)
	case stateSuspended:
		effectiveLimit := min(current.minLimit, limit)
		used, ok := memoryUsed()
		if effectiveLimit == 0 || !ok || used >= effectiveLimit/2 {
			current.resumeGCLocked()
			return nil
		}
		// Minimise the active limit if this caller has a smaller budget.
		current.lowerMemoryLimitLocked(effectiveLimit)
	case stateResumed:
		if limit == 0 {
			return nil
		}
		// GC resumed early; track refs so MaybeFreeOSMemory is skipped until End.
	}
	current.refs++
	return &Suspension{session: current}
}

// End closes `h` if it has not already. When no active handles remain on the
// session, GC settings are restored.
func (h *Suspension) End() {
	if h == nil {
		return
	}
	mu.Lock()
	defer mu.Unlock()
	s := h.session
	if s == nil {
		return
	}
	h.session = nil
	s.refs--
	if s.refs < 0 {
		log.BugTracebackf("Negative suspension session refcount: %d", s.refs)
	}
	if s.refs <= 0 {
		s.resumeGCLocked()
		if current == s {
			current = nil
		}
	}
}

// MaybeFreeOSMemory forces a garbage collection and returns unused memory to
// the OS unless a Suspension handle is currently active.
func MaybeFreeOSMemory() {
	mu.Lock()
	defer mu.Unlock()
	if currentStateLocked() == stateIdle {
		debug.FreeOSMemory()
	}
}
