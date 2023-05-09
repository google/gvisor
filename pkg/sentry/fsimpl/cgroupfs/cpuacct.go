// Copyright 2021 The gVisor Authors.
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

package cgroupfs

import (
	"bytes"
	"fmt"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/kernfs"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/usage"
	"gvisor.dev/gvisor/pkg/sync"
)

// cpuacctController tracks CPU usage for tasks managed by the controller. The
// sentry already tracks CPU usage per task; the controller tries to avoid
// duplicate bookkeeping. When a task moves into a cpuacct cgroup, for currently
// running tasks we simple refer to the tasks themselves when asked to report
// usage. Things get more interesting when tasks leave the cgroup, since we need
// to attribute the usage across multiple cgroups.
//
// On migration, we attribute the task's usage up to the point of migration to
// the src cgroup, and keep track of how much of the overall usage to discount
// at the dst cgroup.
//
// On task exit, we attribute all unaccounted usage to the current cgroup and
// stop tracking the task.
//
// +stateify savable
type cpuacctController struct {
	controllerCommon
	controllerNoResource

	mu sync.Mutex `state:"nosave"`

	// taskCommittedCharges tracks charges for a task already attributed to this
	// cgroup. This is used to avoid double counting usage for live
	// tasks. Protected by mu.
	taskCommittedCharges map[*kernel.Task]usage.CPUStats

	// usage is the cumulative CPU time used by past tasks in this cgroup. Note
	// that this doesn't include usage by live tasks currently in the
	// cgroup. Protected by mu.
	usage usage.CPUStats
}

var _ controller = (*cpuacctController)(nil)

func newCPUAcctController(fs *filesystem) *cpuacctController {
	c := &cpuacctController{
		taskCommittedCharges: make(map[*kernel.Task]usage.CPUStats),
	}
	c.controllerCommon.init(kernel.CgroupControllerCPUAcct, fs)
	return c
}

// Clone implements controller.Clone.
func (c *cpuacctController) Clone() controller {
	new := &cpuacctController{
		taskCommittedCharges: make(map[*kernel.Task]usage.CPUStats),
	}
	new.controllerCommon.cloneFromParent(c)
	return new
}

// AddControlFiles implements controller.AddControlFiles.
func (c *cpuacctController) AddControlFiles(ctx context.Context, creds *auth.Credentials, cg *cgroupInode, contents map[string]kernfs.Inode) {
	cpuacctCG := &cpuacctCgroup{cg}
	contents["cpuacct.stat"] = c.fs.newControllerFile(ctx, creds, &cpuacctStatData{cpuacctCG}, true)
	contents["cpuacct.usage"] = c.fs.newControllerFile(ctx, creds, &cpuacctUsageData{cpuacctCG}, true)
	contents["cpuacct.usage_user"] = c.fs.newControllerFile(ctx, creds, &cpuacctUsageUserData{cpuacctCG}, true)
	contents["cpuacct.usage_sys"] = c.fs.newControllerFile(ctx, creds, &cpuacctUsageSysData{cpuacctCG}, true)
}

// Enter implements controller.Enter.
func (c *cpuacctController) Enter(t *kernel.Task) {}

// Leave implements controller.Leave.
func (c *cpuacctController) Leave(t *kernel.Task) {
	charge := t.CPUStats()
	c.mu.Lock()
	outstandingCharge := charge.DifferenceSince(c.taskCommittedCharges[t])
	c.usage.Accumulate(outstandingCharge)
	delete(c.taskCommittedCharges, t)
	c.mu.Unlock()
}

// PrepareMigrate implements controller.PrepareMigrate.
func (c *cpuacctController) PrepareMigrate(t *kernel.Task, src controller) error {
	return nil
}

// CommitMigrate implements controller.CommitMigrate.
func (c *cpuacctController) CommitMigrate(t *kernel.Task, src controller) {
	charge := t.CPUStats()

	// Commit current charge to src and stop tracking t at src.
	srcCtl := src.(*cpuacctController)
	srcCtl.mu.Lock()
	srcTaskCharge := srcCtl.taskCommittedCharges[t]
	outstandingCharge := charge.DifferenceSince(srcTaskCharge)
	srcCtl.usage.Accumulate(outstandingCharge)
	delete(srcCtl.taskCommittedCharges, t)
	srcCtl.mu.Unlock()

	// Start tracking charge at dst, excluding the charge at src.
	c.mu.Lock()
	c.taskCommittedCharges[t] = charge
	c.mu.Unlock()
}

// AbortMigrate implements controller.AbortMigrate.
func (c *cpuacctController) AbortMigrate(t *kernel.Task, src controller) {}

// +stateify savable
type cpuacctCgroup struct {
	*cgroupInode
}

func (c *cpuacctCgroup) cpuacctController() *cpuacctController {
	return c.controllers[kernel.CgroupControllerCPUAcct].(*cpuacctController)
}

// checklocks:c.fs.tasksMu
func (c *cpuacctCgroup) collectCPUStatsLocked(acc *usage.CPUStats) {
	ctl := c.cpuacctController()
	for t := range c.ts {
		charge := t.CPUStats()
		ctl.mu.Lock()
		outstandingCharge := charge.DifferenceSince(ctl.taskCommittedCharges[t])
		ctl.mu.Unlock()
		acc.Accumulate(outstandingCharge)
	}
	ctl.mu.Lock()
	acc.Accumulate(ctl.usage)
	ctl.mu.Unlock()

	c.forEachChildDir(func(d *dir) {
		cg := cpuacctCgroup{d.cgi}
		cg.collectCPUStatsLocked(acc)
	})
}

func (c *cpuacctCgroup) collectCPUStats() usage.CPUStats {
	c.fs.tasksMu.RLock()
	defer c.fs.tasksMu.RUnlock()

	var cs usage.CPUStats
	c.collectCPUStatsLocked(&cs)
	return cs
}

// +stateify savable
type cpuacctStatData struct {
	*cpuacctCgroup
}

// Generate implements vfs.DynamicBytesSource.Generate.
func (d *cpuacctStatData) Generate(ctx context.Context, buf *bytes.Buffer) error {
	cs := d.collectCPUStats()
	fmt.Fprintf(buf, "user %d\n", linux.ClockTFromDuration(cs.UserTime))
	fmt.Fprintf(buf, "system %d\n", linux.ClockTFromDuration(cs.SysTime))
	return nil
}

// +stateify savable
type cpuacctUsageData struct {
	*cpuacctCgroup
}

// Generate implements vfs.DynamicBytesSource.Generate.
func (d *cpuacctUsageData) Generate(ctx context.Context, buf *bytes.Buffer) error {
	cs := d.collectCPUStats()
	fmt.Fprintf(buf, "%d\n", cs.UserTime.Nanoseconds()+cs.SysTime.Nanoseconds())
	return nil
}

// +stateify savable
type cpuacctUsageUserData struct {
	*cpuacctCgroup
}

// Generate implements vfs.DynamicBytesSource.Generate.
func (d *cpuacctUsageUserData) Generate(ctx context.Context, buf *bytes.Buffer) error {
	cs := d.collectCPUStats()
	fmt.Fprintf(buf, "%d\n", cs.UserTime.Nanoseconds())
	return nil
}

// +stateify savable
type cpuacctUsageSysData struct {
	*cpuacctCgroup
}

// Generate implements vfs.DynamicBytesSource.Generate.
func (d *cpuacctUsageSysData) Generate(ctx context.Context, buf *bytes.Buffer) error {
	cs := d.collectCPUStats()
	fmt.Fprintf(buf, "%d\n", cs.SysTime.Nanoseconds())
	return nil
}
