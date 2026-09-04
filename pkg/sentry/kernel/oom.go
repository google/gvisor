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
	"time"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/atomicbitops"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/usage"
)

// The in-sentry guest OOM killer keeps the sentry alive when a guest workload
// exhausts the sandbox's memory limit. Unlike the host OOM killer (which would
// SIGKILL the entire sentry, tearing down the sandbox, see gVisor issue #2533),
// this killer runs inside the sentry and terminates the guest thread group with
// the highest "badness" score, mirroring Linux's out_of_memory() behavior.
//
// It is driven asynchronously by an oomManager goroutine so that killing never
// happens while holding mm or pgalloc locks (which would risk deadlock). The
// goroutine wakes either from a cheap non-blocking "kick" sent by the allocation
// path when accounted memory crosses the watermark, or from a periodic
// safety-net poll.

const (
	// oomScoreAdjMin/Max mirror Linux OOM_SCORE_ADJ_MIN/MAX. A thread group with
	// oom_score_adj == oomScoreAdjMin is immune from the OOM killer.
	oomScoreAdjMin = -1000
	oomScoreAdjMax = 1000

	// defaultOOMWatermarkPercent is the fraction of the memory limit at which the
	// OOM killer begins terminating processes. Enforcing below 100% leaves
	// headroom so the sentry frees memory before the host limit is reached.
	defaultOOMWatermarkPercent = 95

	// oomMaxKillsPerPass bounds the number of processes killed in a single
	// handlePressure invocation, preventing unbounded work while still allowing
	// several kills when a single one is insufficient.
	oomMaxKillsPerPass = 16

	// oomPollInterval is the safety-net polling period for the OOM manager. Even
	// without a kick from the allocation path, pressure is re-checked this often.
	oomPollInterval = 50 * time.Millisecond

	// oomReclaimPollInterval and oomReclaimTimeout bound how long the manager
	// waits for a killed thread group's memory to be released asynchronously
	// (task exit -> mm cleanup -> pgalloc DecRef) before killing another victim.
	oomReclaimPollInterval = 2 * time.Millisecond
	oomReclaimTimeout      = 2 * time.Second

	// oomKickChanSize is the buffer size of the kick channel. A size of one is
	// sufficient: the manager coalesces pressure signals and re-reads usage.
	oomKickChanSize = 1
)

// oomCandidate is a snapshot of a thread group considered for OOM killing.
type oomCandidate struct {
	// tgid is the thread group's ID in the root PID namespace (for logging).
	tgid int32
	// rssBytes is the thread group's resident set size in bytes.
	rssBytes uint64
	// oomScoreAdj mirrors Linux /proc/<pid>/oom_score_adj, in [-1000, 1000].
	oomScoreAdj int32
	// memCgID is the victim's memory cgroup id, used to attribute the kill in
	// cgroupfs's memory.events (oom_kill).
	memCgID uint32
	// kill sends SIGKILL to the thread group. It must be safe to call without
	// holding the TaskSet lock.
	kill func() error
}

// oomBadness computes a victim-selection score for a process, mirroring Linux's
// oom_badness(): the base score is the resident set size in pages, biased by
// oom_score_adj scaled to the memory limit. Higher scores are killed first. The
// result is at least 1 for any non-immune process so that a process is always
// eligible even with a strongly negative adjustment.
func oomBadness(rssBytes uint64, oomScoreAdj int32, limitBytes uint64) int64 {
	pages := int64(rssBytes / hostarch.PageSize)
	limitPages := int64(limitBytes / hostarch.PageSize)
	// adj is a per-mille bias relative to the total available memory, exactly as
	// in the Linux kernel (adj * totalpages / 1000).
	points := pages + int64(oomScoreAdj)*limitPages/1000
	if points < 1 {
		points = 1
	}
	return points
}

// selectOOMVictim returns the candidate with the highest badness score, skipping
// any candidate that is immune (oom_score_adj == oomScoreAdjMin). It returns
// ok == false when there is no eligible victim.
func selectOOMVictim(cands []oomCandidate, limitBytes uint64) (oomCandidate, bool) {
	bestScore := int64(-1)
	bestIdx := -1
	for i := range cands {
		c := &cands[i]
		if c.oomScoreAdj <= oomScoreAdjMin {
			// Immune from OOM killing.
			continue
		}
		score := oomBadness(c.rssBytes, c.oomScoreAdj, limitBytes)
		if score > bestScore {
			bestScore = score
			bestIdx = i
		}
	}
	if bestIdx < 0 {
		return oomCandidate{}, false
	}
	return cands[bestIdx], true
}

// oomEnv abstracts the kernel state the OOM manager operates on. It exists to
// make the kill loop testable without a full kernel.
type oomEnv interface {
	// usageBytes returns the current total accounted guest+sentry memory.
	usageBytes() uint64
	// limitBytes returns the sandbox memory limit (0 disables enforcement).
	limitBytes() uint64
	// watermarkBytes returns the usage at/above which killing begins.
	watermarkBytes() uint64
	// snapshot returns the current set of OOM candidates.
	snapshot() []oomCandidate
	// overLimitCgroups returns memory cgroups whose usage currently exceeds their
	// configured memory.max limit.
	overLimitCgroups() []cgroupPressure
	// cgroupUsage returns the current combined usage of the given memory cgroup
	// id set, used to wait for per-cgroup reclaim after a kill.
	cgroupUsage(ids map[uint32]struct{}) uint64
	// reclaimEvictable requests that evictable memory (such as page cache) be
	// freed, and waits for eviction to finish or time out. It returns true if any
	// evictions were performed.
	reclaimEvictable() bool
}

// oomManager runs the asynchronous guest OOM killer. It is a runtime-only object
// (the owning Kernel field is state:"nosave"), so it is not stateified.
type oomManager struct {
	env  oomEnv
	kick chan struct{}
	stop chan struct{}

	pollInterval        time.Duration
	reclaimPollInterval time.Duration
	reclaimTimeout      time.Duration

	// oomKills counts the number of thread groups killed by this manager.
	oomKills atomicbitops.Uint64
}

// newOOMManager returns an oomManager with production timing parameters.
func newOOMManager(env oomEnv) *oomManager {
	return &oomManager{
		env:                 env,
		kick:                make(chan struct{}, oomKickChanSize),
		stop:                make(chan struct{}),
		pollInterval:        oomPollInterval,
		reclaimPollInterval: oomReclaimPollInterval,
		reclaimTimeout:      oomReclaimTimeout,
	}
}

// run is the OOM manager goroutine loop.
func (m *oomManager) run() {
	ticker := time.NewTicker(m.pollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-m.stop:
			return
		case <-m.kick:
		case <-ticker.C:
		}
		m.handlePressure()
	}
}

// handlePressure responds to memory pressure, first enforcing the sandbox-wide
// limit and then per-cgroup memory.max limits.
func (m *oomManager) handlePressure() {
	m.handleGlobalPressure()
	m.handleCgroupPressure()
}

// handleGlobalPressure kills processes until sandbox-wide usage falls to/below
// the watermark, no eligible victim remains, or the per-pass kill budget is
// exhausted. It is a no-op when no sandbox-wide limit is configured.
func (m *oomManager) handleGlobalPressure() {
	limit := m.env.limitBytes()
	if limit == 0 {
		return
	}
	wm := m.env.watermarkBytes()
	cur := m.env.usageBytes()
	if cur <= wm {
		return
	}
	// Try to reclaim evictable memory (such as page cache) before killing any
	// process, mirroring Linux page-cache reclaim under memory pressure.
	if m.env.reclaimEvictable() {
		cur = m.env.usageBytes()
		if cur <= wm {
			log.Infof("gVisor OOM: reclaimed evictable memory; usage dropped to %d bytes (<= watermark %d)", cur, wm)
			return
		}
	}
	for i := 0; i < oomMaxKillsPerPass; i++ {
		cur := m.env.usageBytes()
		if cur <= wm {
			return
		}
		cands := m.env.snapshot()
		victim, ok := selectOOMVictim(cands, limit)
		if !ok {
			log.Warningf("gVisor OOM: usage %d bytes over watermark %d but no eligible victim", cur, wm)
			return
		}
		if err := victim.kill(); err != nil {
			// The victim likely exited between snapshot and kill; re-snapshot on
			// the next iteration. Log rather than ignore per error-handling policy.
			log.Warningf("gVisor OOM: failed to SIGKILL tgid %d: %v", victim.tgid, err)
			continue
		}
		m.oomKills.Add(1)
		log.Warningf("gVisor OOM: killed tgid %d (rss=%d bytes, oom_score_adj=%d); usage=%d limit=%d",
			victim.tgid, victim.rssBytes, victim.oomScoreAdj, cur, limit)
		// Wait for the just-killed victim's memory to actually be reclaimed
		// before considering another kill. A SIGKILLed thread group's pages are
		// released asynchronously during teardown, so usage can stay above the
		// watermark for a while after the kill. Killing again immediately would
		// wrongly target innocent siblings, so we wait until usage falls back to
		// the watermark (reclaim succeeded, we are done) and only kill again if
		// it does not (genuine persistent pressure from multiple workloads).
		if m.waitForReclaim(wm) {
			return
		}
	}
}

// waitForReclaim blocks until usage falls to/below target or reclaimTimeout
// elapses. It returns true if usage reached target (reclaim succeeded), or false
// on timeout (pressure persists and another kill may be warranted).
func (m *oomManager) waitForReclaim(target uint64) bool {
	deadline := time.Now().Add(m.reclaimTimeout)
	for {
		if m.env.usageBytes() <= target {
			return true
		}
		if !time.Now().Before(deadline) {
			log.Warningf("gVisor OOM: reclaim did not bring usage to/below watermark %d within %v; usage still %d bytes",
				target, m.reclaimTimeout, m.env.usageBytes())
			return false
		}
		time.Sleep(m.reclaimPollInterval)
	}
}

// handleCgroupPressure enforces per-cgroup memory.max limits: for each memory
// cgroup whose usage exceeds its limit, it kills the highest-badness victim
// charged to that cgroup's subtree, then waits for the cgroup's usage to be
// reclaimed before considering another victim.
func (m *oomManager) handleCgroupPressure() {
	cgs := m.env.overLimitCgroups()
	if len(cgs) == 0 {
		return
	}
	// Attempt to reclaim evictable allocations before killing processes.
	m.env.reclaimEvictable()
	for _, p := range cgs {
		for i := 0; i < oomMaxKillsPerPass; i++ {
			if m.env.cgroupUsage(p.ids) <= p.watermark {
				break
			}
			pool := candidatesInMemCgs(m.env.snapshot(), p.ids)
			victim, ok := selectOOMVictim(pool, p.limit)
			if !ok {
				log.Warningf("gVisor OOM: memory cgroup over limit %d but no eligible victim", p.limit)
				break
			}
			if err := victim.kill(); err != nil {
				// The victim likely exited between snapshot and kill; re-snapshot on
				// the next iteration. Log rather than ignore per error-handling policy.
				log.Warningf("gVisor OOM: failed to SIGKILL tgid %d in over-limit cgroup: %v", victim.tgid, err)
				continue
			}
			m.oomKills.Add(1)
			log.Warningf("gVisor OOM: killed tgid %d (rss=%d bytes, oom_score_adj=%d) for exceeding cgroup memory.max=%d",
				victim.tgid, victim.rssBytes, victim.oomScoreAdj, p.limit)
			if m.waitForCgroupReclaim(p) {
				break
			}
		}
	}
}

// waitForCgroupReclaim blocks until the cgroup's usage falls to/below its
// watermark or reclaimTimeout elapses. It returns true if reclaim succeeded, or
// false on timeout (pressure persists and another kill may be warranted). It
// polls at pollInterval because each poll refreshes per-cgroup accounting, which
// is more expensive than the sandbox-wide fstat.
func (m *oomManager) waitForCgroupReclaim(p cgroupPressure) bool {
	deadline := time.Now().Add(m.reclaimTimeout)
	for {
		if m.env.cgroupUsage(p.ids) <= p.watermark {
			return true
		}
		if !time.Now().Before(deadline) {
			log.Warningf("gVisor OOM: cgroup reclaim did not bring usage to/below watermark %d within %v", p.watermark, m.reclaimTimeout)
			return false
		}
		time.Sleep(m.pollInterval)
	}
}

// candidatesInMemCgs returns the subset of cands whose memory cgroup id is in
// ids (the offending cgroup subtree).
func candidatesInMemCgs(cands []oomCandidate, ids map[uint32]struct{}) []oomCandidate {
	var out []oomCandidate
	for _, c := range cands {
		if _, ok := ids[c.memCgID]; ok {
			out = append(out, c)
		}
	}
	return out
}

// recordOOMKill increments the per-memory-cgroup OOM kill counter for memCgID.
// It is safe for concurrent use.
func (k *Kernel) recordOOMKill(memCgID uint32) {
	k.oomKillsByMemCgMu.Lock()
	defer k.oomKillsByMemCgMu.Unlock()
	if k.oomKillsByMemCg == nil {
		k.oomKillsByMemCg = make(map[uint32]uint64)
	}
	k.oomKillsByMemCg[memCgID]++
}

// OOMKillsForMemCgs returns the total number of guest OOM kills recorded for the
// given set of memory cgroup ids. It backs cgroupfs's memory.events oom_kill.
func (k *Kernel) OOMKillsForMemCgs(ids map[uint32]struct{}) uint64 {
	k.oomKillsByMemCgMu.Lock()
	defer k.oomKillsByMemCgMu.Unlock()
	var total uint64
	for id := range ids {
		total += k.oomKillsByMemCg[id]
	}
	return total
}

// CgroupMemoryPressure describes a memory cgroup whose usage exceeds its
// configured memory.max limit.
type CgroupMemoryPressure struct {
	// IDs is the set of memory cgroup ids composing the offending subtree; it is
	// the pool of candidate victims (tasks charged to any of these ids).
	IDs map[uint32]struct{}
	// Limit is the configured memory.max for the cgroup in bytes.
	Limit uint64
	// Watermark is the usage at/above which killing begins (watermarkPercent of
	// Limit).
	Watermark uint64
}

// CgroupMemoryPressureSource reports memory cgroups over their memory.max limit.
// It is implemented by the cgroup2 filesystem and consulted by the OOM killer to
// enforce per-cgroup limits. All methods must be safe for concurrent use.
type CgroupMemoryPressureSource interface {
	// OverLimitMemoryCgroups returns pressure descriptors for every memory cgroup
	// whose subtree usage exceeds watermarkPercent of its memory.max limit.
	OverLimitMemoryCgroups(k *Kernel, watermarkPercent int) []CgroupMemoryPressure
	// MemoryCgroupUsage returns the current combined usage in bytes of the given
	// set of memory cgroup ids.
	MemoryCgroupUsage(k *Kernel, ids map[uint32]struct{}) uint64
}

// cgroupMemoryPressureSource returns the registered per-cgroup memory pressure
// source (the cgroup2 filesystem), or nil if cgroup v2 is unavailable. Using the
// filesystem singleton directly means enforcement keeps working across
// checkpoint/restore without re-registration.
func (k *Kernel) cgroupMemoryPressureSource() CgroupMemoryPressureSource {
	if k.cgroupRegistry == nil || k.cgroupRegistry.v2fs == nil {
		return nil
	}
	src, ok := k.cgroupRegistry.v2fs.Impl().(CgroupMemoryPressureSource)
	if !ok {
		return nil
	}
	return src
}

// cgroupPressure is the manager-internal view of an over-limit memory cgroup.
type cgroupPressure struct {
	ids       map[uint32]struct{}
	limit     uint64
	watermark uint64
}

// kernelOOMEnv is the production oomEnv backed by a Kernel.
type kernelOOMEnv struct {
	k                *Kernel
	limit            uint64
	watermark        uint64
	watermarkPercent int
}

// usageBytes returns the sandbox's current committed guest memory. It reads the
// MemoryFile's live committed byte count (a cheap fstat of the backing memfd),
// which - unlike usage.MemoryAccounting.Total() - reflects freshly committed
// pages immediately rather than only after a throttled UpdateUsage() scan. This
// is essential for the OOM killer to react to a fast-allocating workload.
func (e *kernelOOMEnv) usageBytes() uint64 {
	if mf := e.k.mf; mf != nil {
		total, err := mf.TotalUsage()
		if err == nil {
			return total
		}
		// Fall back to the (possibly stale) accounting total; log rather than
		// swallow the error per error-handling policy.
		log.Warningf("gVisor OOM: MemoryFile.TotalUsage failed, using accounting total: %v", err)
	}
	return usage.MemoryAccounting.Total()
}
func (e *kernelOOMEnv) limitBytes() uint64     { return e.limit }
func (e *kernelOOMEnv) watermarkBytes() uint64 { return e.watermark }
func (e *kernelOOMEnv) snapshot() []oomCandidate {
	return e.k.oomSnapshot()
}

func (e *kernelOOMEnv) overLimitCgroups() []cgroupPressure {
	src := e.k.cgroupMemoryPressureSource()
	if src == nil {
		return nil
	}
	ps := src.OverLimitMemoryCgroups(e.k, e.watermarkPercent)
	if len(ps) == 0 {
		return nil
	}
	out := make([]cgroupPressure, 0, len(ps))
	for _, p := range ps {
		out = append(out, cgroupPressure{ids: p.IDs, limit: p.Limit, watermark: p.Watermark})
	}
	return out
}

func (e *kernelOOMEnv) cgroupUsage(ids map[uint32]struct{}) uint64 {
	src := e.k.cgroupMemoryPressureSource()
	if src == nil {
		return 0
	}
	return src.MemoryCgroupUsage(e.k, ids)
}

func (e *kernelOOMEnv) reclaimEvictable() bool {
	if mf := e.k.mf; mf != nil {
		if mf.StartEvictions() {
			mf.WaitForEvictionsTimeout(oomReclaimTimeout)
			return true
		}
	}
	return false
}

// oomSnapshot collects the current OOM candidates. RSS is read outside the
// TaskSet lock (only thread group/leader pointers and the atomic oom_score_adj
// are captured under the lock) to avoid nested lock acquisition.
func (k *Kernel) oomSnapshot() []oomCandidate {
	type rawCand struct {
		tg     *ThreadGroup
		leader *Task
		adj    int32
	}
	var raws []rawCand
	k.tasks.ForEachThreadGroup(func(tg *ThreadGroup, leader *Task) {
		if leader == nil {
			return
		}
		raws = append(raws, rawCand{tg: tg, leader: leader, adj: tg.oomScoreAdj.Load()})
	})

	cands := make([]oomCandidate, 0, len(raws))
	for _, r := range raws {
		mmm := r.leader.MemoryManager()
		if mmm == nil {
			// Kernel thread with no user address space; nothing to reclaim.
			continue
		}
		tg := r.tg
		memCgID := r.leader.MemCgID()
		cands = append(cands, oomCandidate{
			tgid:        int32(k.tasks.Root.IDOfThreadGroup(tg)),
			rssBytes:    mmm.ResidentSetSize(),
			oomScoreAdj: r.adj,
			memCgID:     memCgID,
			kill: func() error {
				if err := tg.SendSignal(&linux.SignalInfo{
					Signo: int32(linux.SIGKILL),
					Code:  linux.SI_KERNEL,
				}); err != nil {
					return err
				}
				k.recordOOMKill(memCgID)
				return nil
			},
		})
	}
	return cands
}

// SetOOMKillerConfig configures the in-sentry guest OOM killer. It must be called
// before Kernel.Start. When enabled, the killer is started by Kernel.Start (and
// re-started after restore via RestoreOOMKiller). It always enforces per-cgroup
// memory.max limits, and additionally guards the sandbox-wide limit when one is
// configured (usage.MaximumTotalMemoryBytes > 0). watermarkPercent is the
// percentage of the limit at which killing begins; values outside (0, 100] fall
// back to the default.
func (k *Kernel) SetOOMKillerConfig(enabled bool, watermarkPercent int) {
	k.oomKillerEnabled = enabled
	k.oomWatermarkPercent = watermarkPercent
}

// RestoreOOMKiller re-applies the guest OOM killer configuration and restarts
// the killer after a checkpoint/restore. Both the configuration
// (oomKillerEnabled/oomWatermarkPercent) and the manager goroutine are
// state:"nosave" and do not survive state.Load, so the loader must call this
// once restore completes or the restored sandbox would silently run without OOM
// protection. It is safe to call more than once; maybeStartOOMKiller is
// idempotent.
func (k *Kernel) RestoreOOMKiller(enabled bool, watermarkPercent int) {
	k.SetOOMKillerConfig(enabled, watermarkPercent)
	k.maybeStartOOMKiller()
}

// maybeStartOOMKiller starts the guest OOM killer if it is enabled and not
// already running. It is called from Kernel.Start on boot and from
// Kernel.LoadFrom after a checkpoint/restore, so OOM protection resumes
// automatically once the sandbox is restored.
func (k *Kernel) maybeStartOOMKiller() {
	if !k.oomKillerEnabled {
		return
	}
	// Idempotent: the manager goroutine is state:"nosave", so k.oom is nil after
	// a restore and non-nil once started. Guarding here lets both the boot path
	// (Kernel.Start) and the restore path (Kernel.LoadFrom) call this safely
	// without ever spawning two competing killer goroutines.
	if k.oom != nil {
		return
	}
	watermarkPercent := k.oomWatermarkPercent
	if watermarkPercent <= 0 || watermarkPercent > 100 {
		watermarkPercent = defaultOOMWatermarkPercent
	}
	// A sandbox-wide limit is optional: even without one, the killer enforces
	// per-cgroup memory.max limits. When a sandbox-wide limit is set it also
	// guards total sandbox usage and receives an allocation-path kick.
	limit := usage.MaximumTotalMemoryBytes
	var watermark uint64
	if limit > 0 {
		watermark = limit / 100 * uint64(watermarkPercent)
	}
	env := &kernelOOMEnv{k: k, limit: limit, watermark: watermark, watermarkPercent: watermarkPercent}
	k.oom = newOOMManager(env)
	// Wire sandbox-wide enforcement when a limit is configured: the watermark
	// gives the manager an allocation-path kick for asynchronous reclaim, and the
	// limit itself is the hard ceiling enforced synchronously on the page-fault
	// path (MemoryFile.WaitForOOMHeadroom) so a fast allocator cannot overshoot
	// it. Per-cgroup pressure is caught by the safety-net poll.
	if k.mf != nil && limit > 0 {
		k.mf.SetOOMKick(watermark, limit, k.oom.kick)
	}
	log.Infof("gVisor guest OOM killer started: sandbox limit=%d bytes, watermark=%d bytes (%d%%); synchronous back-pressure=%t; per-cgroup memory.max enforcement enabled", limit, watermark, watermarkPercent, limit > 0)
	go k.oom.run()
}

// The following implements the Linux-compatible /proc/<pid>/oom_score so guest
// tooling (monitoring agents, systemd, orchestrators) sees badness numbers
// consistent with the killer. The killer itself selects victims using the
// finer-grained oomBadness (raw RSS pages) for better resolution between large
// processes; oom_score is the clamped [0, 1000] value Linux exposes via procfs.

// TotalMemoryBytes returns the amount of memory the sandbox reports as total
// system memory. It is the denominator used when normalizing OOM scores,
// mirroring the total-pages term in Linux's oom_badness().
func (k *Kernel) TotalMemoryBytes() uint64 {
	if usage.MaximumTotalMemoryBytes > 0 {
		return usage.MaximumTotalMemoryBytes
	}
	if mf := k.MemoryFile(); mf != nil {
		var used uint64
		if usage.MemoryAccounting != nil {
			used = usage.MemoryAccounting.Total()
		}
		if total := usage.TotalMemory(mf.TotalSize(), used); total > 0 {
			return total
		}
	}
	return usage.MinimumTotalMemoryBytes
}

// calculateOOMScore computes the Linux-style OOM badness score in [0, 1000] for
// a task with resident set size rssBytes and the given oom_score_adj, normalized
// against totalMem. A task with oom_score_adj == oomScoreAdjMin is immune and
// scores 0.
func calculateOOMScore(totalMem, rssBytes uint64, oomScoreAdj int32) int32 {
	if oomScoreAdj <= oomScoreAdjMin {
		return 0
	}
	if totalMem == 0 {
		totalMem = usage.MinimumTotalMemoryBytes
	}
	points := int64(rssBytes*1000/totalMem) + int64(oomScoreAdj)
	if points < 1 {
		return 1
	}
	if points > oomScoreAdjMax {
		return oomScoreAdjMax
	}
	return int32(points)
}

// OOMScore returns the task's OOM badness score in [0, 1000], following Linux's
// oom_badness heuristic. It returns 0 for an immune task (oom_score_adj ==
// oomScoreAdjMin), a dead task, or a task with no address space. This backs
// /proc/<pid>/oom_score.
func (t *Task) OOMScore() int32 {
	adj := t.OOMScoreAdj()
	if adj <= oomScoreAdjMin {
		return 0
	}
	if t.ExitState() == TaskExitDead {
		return 0
	}
	var rss uint64
	var hasMM bool
	t.WithMuLocked(func(t *Task) {
		if memMgr := t.MemoryManager(); memMgr != nil {
			hasMM = true
			rss = memMgr.ResidentSetSize()
		}
	})
	if !hasMM {
		return 0
	}
	return calculateOOMScore(t.k.TotalMemoryBytes(), rss, adj)
}
