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

// Package maxprocs bounds GOMAXPROCS and raises initial GOGC (offsetting
// retained runtime.p spans) during package initialization on >128-CPU hosts.
//
// It uses an init function with minimal imports (no os, strconv, or
// runtime/debug) so it runs before other packages' init allocations; calling
// runtime.GOMAXPROCS also disables Go's periodic cgroup GOMAXPROCS updates.
package maxprocs

import (
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"

	"gvisor.dev/gvisor/pkg/gohacks"
)

const (
	threshold          = 128
	maxProcs           = 8
	deadBytesPerP      = 16 << 10 // 2-page span per runtime.p (~15.6 KiB in Go 1.27).
	defaultHeapMinimum = 4 << 20
	defaultHeapTrigger = defaultHeapMinimum * 61 / 64 // runtime/mgcpacer.go maxTriggerRatioNum.
	defaultGCPercent   = 100
	maxGCPercent       = 200
)

var (
	lowered          bool
	needReset        atomic.Bool
	resetMu          sync.Mutex
	prevGCPercent    int32
	appliedGCPercent int32
)

func init() {
	if cur := runtime.GOMAXPROCS(0); cur > threshold {
		initMaxProcs(cur, syscall.Getenv, gohacks.NumGC)
	}
}

func initMaxProcs(cur int, lookupEnv func(string) (string, bool), numGC func() uint32) {
	if cur <= threshold {
		return
	}
	v, ok := lookupEnv("GOMAXPROCS")
	n := bound(cur, ok && gomaxprocsEnvSet(v))
	if n == 0 {
		return
	}
	runtime.GOMAXPROCS(n)
	lowered = true

	gogc, gogcOK := lookupEnv("GOGC")
	memLimit, memLimitOK := lookupEnv("GOMEMLIMIT")
	if !(gogcOK && gogcEnvSet(gogc)) && !(memLimitOK && gomemlimitEnvSet(memLimit)) && numGC() == 0 {
		if target := gcPercent(cur); target > defaultGCPercent {
			prev := gohacks.SetGCPercent(target)
			prevGCPercent = prev
			appliedGCPercent = target
			needReset.Store(true)
		}
	}
}

func bound(cur int, envSet bool) int {
	if envSet || cur <= threshold {
		return 0
	}
	return maxProcs
}

func gcPercent(initial int) int32 {
	if initial <= threshold {
		return defaultGCPercent
	}
	const maxDeadPs = (int64(maxGCPercent-defaultGCPercent)*defaultHeapTrigger + defaultGCPercent*deadBytesPerP - 1) / (defaultGCPercent * deadBytesPerP)
	deadBytes := min(int64(initial)-maxProcs, maxDeadPs) * deadBytesPerP
	extra := int32((deadBytes*defaultGCPercent + defaultHeapTrigger - 1) / defaultHeapTrigger)
	return min(maxGCPercent, defaultGCPercent+extra)
}

// ResetGCPercent restores the pre-init GC percentage unless GOGC was changed to
// a different value since init. It must not be called concurrently with
// debug.SetGCPercent.
func ResetGCPercent() {
	if !needReset.Load() {
		return
	}
	resetGCPercentSlow()
}

func resetGCPercentSlow() {
	resetMu.Lock()
	defer resetMu.Unlock()
	if !needReset.Load() {
		return
	}
	applied := appliedGCPercent
	prev := prevGCPercent
	appliedGCPercent = 0
	prevGCPercent = 0
	switch cur := gohacks.SetGCPercent(-1); cur {
	case applied:
		gohacks.SetGCPercent(prev)
	case -1:
	default:
		gohacks.SetGCPercent(cur)
	}
	needReset.Store(false)
}

// gomaxprocsEnvSet, gogcEnvSet, and gomemlimitEnvSet match the Go runtime's
// schedinit, readGOGC, and readGOMEMLIMIT environment parsing.
func gomaxprocsEnvSet(val string) bool {
	n, ok := parseInt32(val)
	return ok && n > 0
}

func gogcEnvSet(val string) bool {
	if val == "off" {
		return true
	}
	_, ok := parseInt32(val)
	return ok
}

func gomemlimitEnvSet(val string) bool {
	return val != "" && val != "off"
}

func parseInt32(s string) (int32, bool) {
	if s == "" {
		return 0, false
	}
	neg := false
	switch s[0] {
	case '-':
		neg = true
		s = s[1:]
	case '+':
		s = s[1:]
	}
	if s == "" {
		return 0, false
	}
	const maxAbs = uint64(1) << 31
	limit := maxAbs - 1
	if neg {
		limit = maxAbs
	}
	var n uint64
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < '0' || c > '9' {
			return 0, false
		}
		n = n*10 + uint64(c-'0')
		if n > limit {
			return 0, false
		}
	}
	if neg {
		return int32(-int64(n)), true
	}
	return int32(n), true
}
