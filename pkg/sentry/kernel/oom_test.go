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

package kernel

import (
	"errors"
	"sync"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/hostarch"
)

const testPage = uint64(hostarch.PageSize)

func TestOOMBadness(t *testing.T) {
	const limit = 1000 * testPage
	for _, tc := range []struct {
		name    string
		rss     uint64
		adj     int32
		wantMin int64 // lower bound; exact value asserted where deterministic
		want    int64 // if non-zero, assert exact
	}{
		{name: "plain", rss: 100 * testPage, adj: 0, want: 100},
		{name: "adj_positive_bias", rss: 100 * testPage, adj: 100, want: 100 + 100},
		{name: "adj_negative_bias", rss: 500 * testPage, adj: -100, want: 500 - 100},
		{name: "floor_at_one", rss: 0, adj: 0, want: 1},
		{name: "negative_clamped_to_one", rss: 10 * testPage, adj: -1000, want: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := oomBadness(tc.rss, tc.adj, limit)
			if tc.want != 0 && got != tc.want {
				t.Errorf("oomBadness(%d,%d,%d) = %d, want %d", tc.rss, tc.adj, limit, got, tc.want)
			}
			if got < 1 {
				t.Errorf("oomBadness returned %d, must be >= 1", got)
			}
		})
	}
}

func TestSelectOOMVictimHighestRSS(t *testing.T) {
	const limit = 1000 * testPage
	cands := []oomCandidate{
		{tgid: 1, rssBytes: 10 * testPage, oomScoreAdj: 0},
		{tgid: 2, rssBytes: 500 * testPage, oomScoreAdj: 0},
		{tgid: 3, rssBytes: 100 * testPage, oomScoreAdj: 0},
	}
	v, ok := selectOOMVictim(cands, limit)
	if !ok || v.tgid != 2 {
		t.Errorf("selectOOMVictim = (%+v, %v), want tgid 2", v, ok)
	}
}

func TestSelectOOMVictimAdjBias(t *testing.T) {
	const limit = 1000 * testPage
	// tgid 1 has less RSS but a large positive adj, which should make it the
	// victim over the larger-RSS but adj=0 process.
	cands := []oomCandidate{
		{tgid: 1, rssBytes: 100 * testPage, oomScoreAdj: 500}, // 100 + 500 = 600
		{tgid: 2, rssBytes: 400 * testPage, oomScoreAdj: 0},   // 400
	}
	v, ok := selectOOMVictim(cands, limit)
	if !ok || v.tgid != 1 {
		t.Errorf("selectOOMVictim = (%+v, %v), want tgid 1 (adj bias)", v, ok)
	}
}

func TestSelectOOMVictimImmune(t *testing.T) {
	const limit = 1000 * testPage
	// The largest process is immune (adj == oomScoreAdjMin); the next largest
	// non-immune process must be chosen.
	cands := []oomCandidate{
		{tgid: 1, rssBytes: 900 * testPage, oomScoreAdj: oomScoreAdjMin},
		{tgid: 2, rssBytes: 200 * testPage, oomScoreAdj: 0},
		{tgid: 3, rssBytes: 100 * testPage, oomScoreAdj: 0},
	}
	v, ok := selectOOMVictim(cands, limit)
	if !ok || v.tgid != 2 {
		t.Errorf("selectOOMVictim = (%+v, %v), want tgid 2 (immune skipped)", v, ok)
	}
}

func TestSelectOOMVictimAllImmune(t *testing.T) {
	const limit = 1000 * testPage
	cands := []oomCandidate{
		{tgid: 1, rssBytes: 900 * testPage, oomScoreAdj: oomScoreAdjMin},
		{tgid: 2, rssBytes: 200 * testPage, oomScoreAdj: oomScoreAdjMin},
	}
	if _, ok := selectOOMVictim(cands, limit); ok {
		t.Error("selectOOMVictim returned a victim, want none (all immune)")
	}
}

func TestSelectOOMVictimEmpty(t *testing.T) {
	if _, ok := selectOOMVictim(nil, 1000*testPage); ok {
		t.Error("selectOOMVictim(nil) returned a victim, want none")
	}
}

// fakeProc is a simulated guest process for the manager tests.
type fakeProc struct {
	tgid    int32
	rss     uint64
	adj     int32
	memCgID uint32
	alive   bool
	killErr error
}

// fakeOOMEnv is a test oomEnv where killing a process immediately frees its
// memory (simulating synchronous reclaim).
type fakeOOMEnv struct {
	mu             sync.Mutex
	procs          []*fakeProc
	limit          uint64
	watermark      uint64
	kills          int
	evictableBytes uint64
	evictCalls     int
	cgPressure     []cgroupPressure
	cgUsage        func(ids map[uint32]struct{}) uint64
}

func (e *fakeOOMEnv) usageBytes() uint64 {
	e.mu.Lock()
	defer e.mu.Unlock()
	var total uint64
	for _, p := range e.procs {
		if p.alive {
			total += p.rss
		}
	}
	total += e.evictableBytes
	return total
}

func (e *fakeOOMEnv) limitBytes() uint64     { return e.limit }
func (e *fakeOOMEnv) watermarkBytes() uint64 { return e.watermark }

func (e *fakeOOMEnv) reclaimEvictable() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.evictCalls++
	if e.evictableBytes > 0 {
		e.evictableBytes = 0
		return true
	}
	return false
}

func (e *fakeOOMEnv) overLimitCgroups() []cgroupPressure {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.cgPressure
}

func (e *fakeOOMEnv) cgroupUsage(ids map[uint32]struct{}) uint64 {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.cgUsage != nil {
		return e.cgUsage(ids)
	}
	var total uint64
	for _, p := range e.procs {
		if p.alive {
			if _, ok := ids[p.memCgID]; ok {
				total += p.rss
			}
		}
	}
	return total
}

func (e *fakeOOMEnv) snapshot() []oomCandidate {
	e.mu.Lock()
	defer e.mu.Unlock()
	var cands []oomCandidate
	for _, p := range e.procs {
		if !p.alive {
			continue
		}
		p := p
		cands = append(cands, oomCandidate{
			tgid:        p.tgid,
			rssBytes:    p.rss,
			oomScoreAdj: p.adj,
			memCgID:     p.memCgID,
			kill: func() error {
				e.mu.Lock()
				defer e.mu.Unlock()
				if p.killErr != nil {
					p.alive = false
					return p.killErr
				}
				p.alive = false
				e.kills++
				return nil
			},
		})
	}
	return cands
}

func newTestManager(env oomEnv) *oomManager {
	m := newOOMManager(env)
	// Shrink timings so the test is fast; drive exclusively via kick. The fake
	// env reclaims synchronously, so between kills the manager hits the reclaim
	// timeout path; keep it short to avoid slow tests.
	m.pollInterval = time.Hour
	m.reclaimPollInterval = time.Millisecond
	m.reclaimTimeout = 20 * time.Millisecond
	return m
}

func TestHandlePressureKillsUntilUnderWatermark(t *testing.T) {
	env := &fakeOOMEnv{
		limit:     1000 * testPage,
		watermark: 800 * testPage,
		procs: []*fakeProc{
			{tgid: 1, rss: 300 * testPage, adj: 0, alive: true},
			{tgid: 2, rss: 300 * testPage, adj: 0, alive: true},
			{tgid: 3, rss: 300 * testPage, adj: 0, alive: true},
			{tgid: 4, rss: 300 * testPage, adj: 0, alive: true}, // total 1200 > wm
		},
	}
	m := newTestManager(env)
	m.handlePressure()
	if got := env.usageBytes(); got > env.watermark {
		t.Errorf("usage after handlePressure = %d, want <= watermark %d", got, env.watermark)
	}
	// Exactly two kills bring usage to 600 (<= 800); a third would be wasteful.
	if env.kills != 2 {
		t.Errorf("kills = %d, want 2", env.kills)
	}
}

func TestHandlePressureNoVictimTerminates(t *testing.T) {
	// Over watermark but every process is immune: must return promptly without
	// spinning or killing.
	env := &fakeOOMEnv{
		limit:     1000 * testPage,
		watermark: 100 * testPage,
		procs: []*fakeProc{
			{tgid: 1, rss: 500 * testPage, adj: oomScoreAdjMin, alive: true},
		},
	}
	m := newTestManager(env)
	done := make(chan struct{})
	go func() {
		m.handlePressure()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("handlePressure did not terminate with no eligible victim")
	}
	if env.kills != 0 {
		t.Errorf("kills = %d, want 0", env.kills)
	}
}

func TestHandlePressureUnderWatermarkNoKill(t *testing.T) {
	env := &fakeOOMEnv{
		limit:     1000 * testPage,
		watermark: 800 * testPage,
		procs: []*fakeProc{
			{tgid: 1, rss: 100 * testPage, adj: 0, alive: true},
		},
	}
	m := newTestManager(env)
	m.handlePressure()
	if env.kills != 0 {
		t.Errorf("kills = %d, want 0 (under watermark)", env.kills)
	}
}

func TestManagerRunKickTriggersKill(t *testing.T) {
	env := &fakeOOMEnv{
		limit:     1000 * testPage,
		watermark: 500 * testPage,
		procs: []*fakeProc{
			{tgid: 1, rss: 700 * testPage, adj: 0, alive: true},
		},
	}
	m := newTestManager(env)
	go m.run()
	defer close(m.stop)

	m.kick <- struct{}{}

	deadline := time.After(5 * time.Second)
	for env.usageBytes() > env.watermark {
		select {
		case <-deadline:
			t.Fatalf("manager did not reduce usage below watermark; usage=%d", env.usageBytes())
		case <-time.After(5 * time.Millisecond):
		}
	}
	if got := m.oomKills.Load(); got == 0 {
		t.Error("oomKills counter not incremented")
	}
}

// TestOOMKillsPerMemCg verifies per-memory-cgroup OOM kill accounting used by
// cgroupfs's memory.events.
func TestOOMKillsPerMemCg(t *testing.T) {
	k := &Kernel{}
	k.recordOOMKill(5)
	k.recordOOMKill(5)
	k.recordOOMKill(7)
	if got := k.OOMKillsForMemCgs(map[uint32]struct{}{5: {}}); got != 2 {
		t.Errorf("OOMKillsForMemCgs({5}) = %d, want 2", got)
	}
	if got := k.OOMKillsForMemCgs(map[uint32]struct{}{5: {}, 7: {}}); got != 3 {
		t.Errorf("OOMKillsForMemCgs({5,7}) = %d, want 3", got)
	}
	if got := k.OOMKillsForMemCgs(map[uint32]struct{}{9: {}}); got != 0 {
		t.Errorf("OOMKillsForMemCgs({9}) = %d, want 0", got)
	}
}

// TestHandlePressureReclaimsEvictableBeforeKill verifies that when memory
// pressure can be resolved by evicting evictable memory (page cache), no
// processes are killed.
func TestHandlePressureReclaimsEvictableBeforeKill(t *testing.T) {
	env := &fakeOOMEnv{
		limit:          1000 * testPage,
		watermark:      800 * testPage,
		evictableBytes: 300 * testPage,
		procs: []*fakeProc{
			{tgid: 1, rss: 600 * testPage, adj: 0, alive: true},
		}, // Total usage = 600 + 300 = 900 > watermark 800
	}
	m := newTestManager(env)
	m.handlePressure()
	if env.evictCalls == 0 {
		t.Error("expected reclaimEvictable to be called before killing")
	}
	if env.kills != 0 {
		t.Errorf("kills = %d, want 0 (pressure resolved by evictable reclaim)", env.kills)
	}
	if got := env.usageBytes(); got > env.watermark {
		t.Errorf("usage = %d, want <= watermark %d", got, env.watermark)
	}
}

// TestHandleCgroupPressure verifies that cgroup pressure kills only processes
// charged to the offending cgroup, leaving larger processes in other cgroups
// untouched.
func TestHandleCgroupPressure(t *testing.T) {
	env := &fakeOOMEnv{
		limit:     2000 * testPage,
		watermark: 1800 * testPage,
		cgPressure: []cgroupPressure{
			{
				ids:       map[uint32]struct{}{1: {}},
				limit:     500 * testPage,
				watermark: 400 * testPage,
			},
		},
		procs: []*fakeProc{
			// PID 1 is in cgroup 1 and exceeds its 400 watermark.
			{tgid: 1, rss: 450 * testPage, memCgID: 1, alive: true},
			// PID 2 is in cgroup 2 with a larger RSS, but cgroup 2 is not over limit.
			{tgid: 2, rss: 900 * testPage, memCgID: 2, alive: true},
		},
	}
	m := newTestManager(env)
	m.handlePressure()
	if env.kills != 1 {
		t.Fatalf("kills = %d, want 1", env.kills)
	}
	if env.procs[0].alive {
		t.Error("expected cgroup 1 victim (tgid 1) to be killed")
	}
	if !env.procs[1].alive {
		t.Error("innocent cgroup 2 process (tgid 2) was killed")
	}
}

// TestCalculateOOMScore tests normalization, scaling, clamping, and immunity in
// calculateOOMScore.
func TestCalculateOOMScore(t *testing.T) {
	const total = 1000 * testPage
	for _, tc := range []struct {
		name     string
		totalMem uint64
		rss      uint64
		adj      int32
		want     int32
	}{
		{name: "immune", totalMem: total, rss: 500 * testPage, adj: oomScoreAdjMin, want: 0},
		{name: "half_memory_zero_adj", totalMem: total, rss: 500 * testPage, adj: 0, want: 500},
		{name: "adj_bias_positive", totalMem: total, rss: 200 * testPage, adj: 300, want: 500},
		{name: "clamp_at_max", totalMem: total, rss: 900 * testPage, adj: 500, want: oomScoreAdjMax},
		{name: "clamp_at_floor_one", totalMem: total, rss: 10 * testPage, adj: -500, want: 1},
		{name: "fallback_totalmem_zero", totalMem: 0, rss: 0, adj: 0, want: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := calculateOOMScore(tc.totalMem, tc.rss, tc.adj)
			if got != tc.want {
				t.Errorf("calculateOOMScore(%d, %d, %d) = %d, want %d", tc.totalMem, tc.rss, tc.adj, got, tc.want)
			}
		})
	}
}

// TestHandlePressureKillErrorContinues verifies that an error when killing a
// candidate (e.g. process already dead) is logged and the manager continues to
// the next candidate.
func TestHandlePressureKillErrorContinues(t *testing.T) {
	env := &fakeOOMEnv{
		limit:     1000 * testPage,
		watermark: 200 * testPage, // 300 (PID 2) > 200, so PID 2 must be killed after PID 1 exits
		procs: []*fakeProc{
			// PID 1 fails to kill (e.g. exited concurrently).
			{tgid: 1, rss: 400 * testPage, adj: 0, alive: true, killErr: errors.New("already exited")},
			// PID 2 can be killed.
			{tgid: 2, rss: 300 * testPage, adj: 0, alive: true},
		},
	}
	m := newTestManager(env)
	m.handlePressure()
	if !env.procs[1].alive && env.kills == 1 {
		// Success: continued past PID 1's error to kill PID 2.
	} else {
		t.Errorf("expected PID 2 to be killed after PID 1 kill error; kills=%d", env.kills)
	}
}

// TestHandlePressureKillsPerPassBudget verifies that handlePressure terminates
// after oomMaxKillsPerPass kills even if memory remains above the watermark.
func TestHandlePressureKillsPerPassBudget(t *testing.T) {
	var procs []*fakeProc
	for i := 1; i <= 25; i++ {
		procs = append(procs, &fakeProc{tgid: int32(i), rss: 100 * testPage, alive: true})
	}
	env := &fakeOOMEnv{
		limit:     5000 * testPage,
		watermark: 100 * testPage, // impossible to reach in 16 kills
		procs:     procs,
	}
	m := newTestManager(env)
	m.handlePressure()
	if env.kills != oomMaxKillsPerPass {
		t.Errorf("kills = %d, want oomMaxKillsPerPass (%d)", env.kills, oomMaxKillsPerPass)
	}
}

// TestKernelOOMKillerConfig verifies SetOOMKillerConfig and idempotency of
// maybeStartOOMKiller.
func TestKernelOOMKillerConfig(t *testing.T) {
	k := &Kernel{}
	k.SetOOMKillerConfig(true, 85)
	if !k.oomKillerEnabled || k.oomWatermarkPercent != 85 {
		t.Errorf("SetOOMKillerConfig: enabled=%v, pct=%d", k.oomKillerEnabled, k.oomWatermarkPercent)
	}

	// Start once: k.oom becomes non-nil.
	k.maybeStartOOMKiller()
	if k.oom == nil {
		t.Fatal("maybeStartOOMKiller did not initialize k.oom")
	}
	orig := k.oom

	// Idempotency: calling again should not re-initialize or spawn a duplicate.
	k.maybeStartOOMKiller()
	if k.oom != orig {
		t.Error("maybeStartOOMKiller was not idempotent")
	}
	close(k.oom.stop)
}

// TestHandlePressureMultipleHogsSequentialSparesSibling tests that when
// multiple large hogs push usage over the watermark, the killer terminates the
// hogs sequentially until usage is back under the watermark, sparing an
// innocent low-usage sibling.
func TestHandlePressureMultipleHogsSequentialSparesSibling(t *testing.T) {
	sibling := &fakeProc{tgid: 100, rss: 50 * testPage, adj: 0, alive: true}
	env := &fakeOOMEnv{
		limit:     1000 * testPage,
		watermark: 400 * testPage,
		procs: []*fakeProc{
			{tgid: 1, rss: 500 * testPage, adj: 0, alive: true},
			{tgid: 2, rss: 500 * testPage, adj: 0, alive: true},
			sibling,
		},
	}
	m := newTestManager(env)
	m.handlePressure()

	if !sibling.alive {
		t.Fatal("innocent sibling was killed during multi-hog pressure handling")
	}
	if env.kills != 2 {
		t.Errorf("kills = %d, want 2", env.kills)
	}
	if got := env.usageBytes(); got > env.watermark {
		t.Errorf("usage = %d, want <= %d", got, env.watermark)
	}
}

// TestHandlePressureImmuneHogSpared tests that an immune hog (oom_score_adj=-1000)
// is never killed by the manager, even if it is the largest memory consumer
// keeping usage above the watermark.
func TestHandlePressureImmuneHogSpared(t *testing.T) {
	immuneHog := &fakeProc{tgid: 1, rss: 900 * testPage, adj: oomScoreAdjMin, alive: true}
	smallNonImmune := &fakeProc{tgid: 2, rss: 150 * testPage, adj: 0, alive: true}
	env := &fakeOOMEnv{
		limit:     1000 * testPage,
		watermark: 800 * testPage,
		procs: []*fakeProc{
			immuneHog,
			smallNonImmune,
		},
	}
	m := newTestManager(env)
	m.handlePressure()

	if !immuneHog.alive {
		t.Fatal("immune hog was killed; must be spared")
	}
	if smallNonImmune.alive {
		t.Fatal("small non-immune proc should have been killed as only eligible victim")
	}
	if env.kills != 1 {
		t.Errorf("kills = %d, want 1", env.kills)
	}
}

// TestCalculateOOMScoreProperties exercises calculateOOMScore across boundary
// conditions and a wide range of permutated inputs to verify that it never
// panics, overflows, or produces scores outside the valid [0, 1000] range.
func TestCalculateOOMScoreProperties(t *testing.T) {
	testValues := []uint64{0, 1, 100, 4096, 1 << 20, 1 << 30, 1 << 40, ^uint64(0)}
	adjustments := []int32{-1000, -999, -500, 0, 500, 999, 1000}
	for _, rss := range testValues {
		for _, total := range testValues {
			for _, adj := range adjustments {
				score := calculateOOMScore(rss, total, adj)
				if adj <= oomScoreAdjMin {
					if score != 0 {
						t.Fatalf("expected 0 for immune rss=%d total=%d adj=%d, got %d", rss, total, adj, score)
					}
				} else if score < 1 || score > 1000 {
					t.Fatalf("score %d out of bounds [1, 1000] for rss=%d total=%d adj=%d", score, rss, total, adj)
				}
			}
		}
	}
}
