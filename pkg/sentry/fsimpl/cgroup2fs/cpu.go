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

package cgroup2fs

import (
	"bytes"
	"fmt"
	"math"
	"strconv"
	"strings"

	"gvisor.dev/gvisor/pkg/atomicbitops"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/usage"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/usermem"
)

// +stateify savable
type cpu struct {
	c        *cgroup
	parent   *cpu
	detached atomicbitops.Bool

	mu cpuMutex `state:"nosave"`

	// baselineCharges records the baseline CPU time snapshot for each task
	// right when it entered or migrated into this cgroup (via enter or attach).
	// When calculating usage for live tasks, subtracting this baseline ensures we
	// only attribute CPU time burned while residing inside this cgroup.
	// +checklocks:mu
	baselineCharges map[*kernel.Task]usage.CPUStats

	// usage is the cumulative CPU time used by past tasks in this cgroup. Note
	// that this doesn't include usage by live tasks currently in the cgroup.
	// +checklocks:mu
	usage usage.CPUStats

	// weight is the CPU weight representing the cpu.weight value.
	// +checkatomic
	weight atomicbitops.Int64
	// maxUSec is the CPU quota limit representing the cpu.max quota.
	// +checkatomic
	maxUSec atomicbitops.Int64
	// periodUSec is the CPU period limit representing the cpu.max period.
	// +checkatomic
	periodUSec atomicbitops.Int64
}

// canEnter implements controller.canEnter.
func (cc *cpu) canEnter(ctx context.Context, t *kernel.Task) bool { return true }

// cancelEnter implements controller.cancelEnter.
func (cc *cpu) cancelEnter(ctx context.Context, t *kernel.Task) {}

// enter implements controller.enter.
func (cc *cpu) enter(ctx context.Context, t *kernel.Task) {
	cc.mu.Lock()
	defer cc.mu.Unlock()
	cc.baselineCharges[t] = t.CPUStats()
}

func (cc *cpu) commitTaskCharges(t *kernel.Task, charge usage.CPUStats) {
	cc.mu.Lock()
	outstandingCharge := charge.DifferenceSince(cc.baselineCharges[t])
	cc.usage.Accumulate(outstandingCharge)
	delete(cc.baselineCharges, t)
	cc.mu.Unlock()
}

// exit implements controller.exit.
func (cc *cpu) exit(ctx context.Context, t *kernel.Task) {
	cc.commitTaskCharges(t, t.CPUStats())
}

// canAttach implements controller.canAttach.
func (cc *cpu) canAttach(ctx context.Context, actx *attachCtx) bool { return true }

// cancelAttach implements controller.cancelAttach.
func (cc *cpu) cancelAttach(ctx context.Context, actx *attachCtx) {}

// attach implements controller.attach.
func (cc *cpu) attach(ctx context.Context, actx *attachCtx) {
	for t := range actx.tasks {
		charge := t.CPUStats()
		if oldNode := actx.oldNodes[t]; oldNode != nil {
			if oldCtrl := oldNode.closestCtrls.Load()[kernel.Cgroup2CPU]; oldCtrl != nil {
				if oldCPU, ok := oldCtrl.(*cpu); ok && oldCPU != cc {
					oldCPU.commitTaskCharges(t, charge)
				}
			}
		}
		cc.mu.Lock()
		cc.baselineCharges[t] = charge
		cc.mu.Unlock()
	}
}

// +checklocksread:cc.c.fs.treeMu
// +checklocksread:cc.c.fs.tasksMu
func (cc *cpu) collectCPUStatsLocked(acc *usage.CPUStats) {
	for t := range cc.c.tasks {
		charge := t.CPUStats()
		cc.mu.Lock()
		outstandingCharge := charge.DifferenceSince(cc.baselineCharges[t])
		cc.mu.Unlock()
		acc.Accumulate(outstandingCharge)
	}
	cc.mu.Lock()
	acc.Accumulate(cc.usage)
	cc.mu.Unlock()

	for child := range cc.c.children {
		if childCtrl := child.closestCtrls.Load()[kernel.Cgroup2CPU]; childCtrl != nil {
			if cpuChild, ok := childCtrl.(*cpu); ok && cpuChild.c == child {
				cpuChild.collectCPUStatsLocked(acc) // +checklocksforce: cpuChild shares cc.c.fs locks
			}
		}
	}
}

func (cc *cpu) collectCPUStats() usage.CPUStats {
	cc.c.fs.treeMu.RLock()
	defer cc.c.fs.treeMu.RUnlock()
	cc.c.fs.tasksMu.RLock()
	defer cc.c.fs.tasksMu.RUnlock()

	var cs usage.CPUStats
	cc.collectCPUStatsLocked(&cs)
	return cs
}

// interfaceFiles implements controller.interfaceFiles.
func (cc *cpu) interfaceFiles() []interfaceFile {
	return []interfaceFile{
		{name: "cpu.stat", source: &cpuStat{cc: cc}, perm: 0444, showAtRoot: true},
		{name: "cpu.max", source: &cpuMax{cc: cc}, perm: 0644},
		{name: "cpu.weight", source: &cpuWeight{cc: cc}, perm: 0644},
	}
}

// interfaceFileNames implements controller.interfaceFileNames.
func (cc *cpu) interfaceFileNames() []string {
	return []string{"cpu.stat", "cpu.max", "cpu.weight"}
}

// +stateify savable
type cpuStat struct {
	cc *cpu
}

// Generate implements vfs.DynamicBytesSource.Generate.
func (cstat *cpuStat) Generate(ctx context.Context, buf *bytes.Buffer) error {
	cs := cstat.cc.collectCPUStats()
	usageUSec := (cs.UserTime + cs.SysTime).Microseconds()
	userUSec := cs.UserTime.Microseconds()
	sysUSec := cs.SysTime.Microseconds()
	fmt.Fprintf(buf, "usage_usec %d\nuser_usec %d\nsystem_usec %d\nnice_usec 0\nnr_periods 0\nnr_throttled 0\nthrottled_usec 0\nnr_bursts 0\nburst_usec 0\n", usageUSec, userUSec, sysUSec)
	return nil
}

// +stateify savable
type cpuMax struct {
	cc *cpu
}

// Generate implements vfs.DynamicBytesSource.Generate.
func (cm *cpuMax) Generate(ctx context.Context, buf *bytes.Buffer) error {
	quota := cm.cc.maxUSec.Load()
	period := cm.cc.periodUSec.Load()
	if quota == math.MaxInt64 {
		fmt.Fprintf(buf, "max %d\n", period)
	} else {
		fmt.Fprintf(buf, "%d %d\n", quota, period)
	}
	return nil
}

// Write implements vfs.WritableDynamicBytesSource.Write.
//
// Note: Although cpu.max is writable and remembers the value, nothing is enforced.
func (cm *cpuMax) Write(ctx context.Context, _ *vfs.FileDescription, src usermem.IOSequence, offset int64) (int64, error) {
	if src.NumBytes() > 1024 {
		return 0, linuxerr.EINVAL
	}
	buf := make([]byte, src.NumBytes())
	if _, err := src.CopyIn(ctx, buf); err != nil {
		return 0, err
	}
	str := strings.TrimSpace(string(buf))
	fields := strings.Fields(str)
	if len(fields) < 1 || len(fields) > 2 {
		return 0, linuxerr.EINVAL
	}

	var quota int64
	if fields[0] == "max" {
		quota = math.MaxInt64
	} else {
		val, err := strconv.ParseInt(fields[0], 10, 64)
		if err != nil || val <= 0 {
			return 0, linuxerr.EINVAL
		}
		quota = val
	}

	var period int64
	if len(fields) == 2 {
		val, err := strconv.ParseInt(fields[1], 10, 64)
		if err != nil || val <= 0 {
			return 0, linuxerr.EINVAL
		}
		period = val
	} else {
		period = cm.cc.periodUSec.Load()
	}

	cm.cc.maxUSec.Store(quota)
	cm.cc.periodUSec.Store(period)
	return int64(len(buf)), nil
}

// +stateify savable
type cpuWeight struct {
	cc *cpu
}

// Generate implements vfs.DynamicBytesSource.Generate.
func (cw *cpuWeight) Generate(ctx context.Context, buf *bytes.Buffer) error {
	fmt.Fprintf(buf, "%d\n", cw.cc.weight.Load())
	return nil
}

// Write implements vfs.WritableDynamicBytesSource.Write.
//
// Note: Although cpu.weight is writable and remembers the value, nothing is enforced.
func (cw *cpuWeight) Write(ctx context.Context, _ *vfs.FileDescription, src usermem.IOSequence, offset int64) (int64, error) {
	if src.NumBytes() > 1024 {
		return 0, linuxerr.EINVAL
	}
	buf := make([]byte, src.NumBytes())
	if _, err := src.CopyIn(ctx, buf); err != nil {
		return 0, err
	}
	str := strings.TrimSpace(string(buf))
	val, err := strconv.ParseInt(str, 10, 64)
	if err != nil {
		return 0, linuxerr.EINVAL
	}
	if val < 1 || val > 10000 {
		return 0, linuxerr.ERANGE
	}
	cw.cc.weight.Store(val)
	return int64(len(buf)), nil
}

// detach implements controller.detach.
func (cc *cpu) detach() {
	cc.detached.Store(true)
}

// isActive implements controller.isActive.
func (cc *cpu) isActive() bool {
	return !cc.detached.Load()
}
