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
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/usage"
)

// +stateify savable
type cpuacctController struct {
	controllerCommon
}

var _ controller = (*cpuacctController)(nil)

func newCPUAcctController(fs *filesystem) *cpuacctController {
	c := &cpuacctController{}
	c.controllerCommon.init(controllerCPUAcct, fs)
	return c
}

// AddControlFiles implements controller.AddControlFiles.
func (c *cpuacctController) AddControlFiles(ctx context.Context, creds *auth.Credentials, cg *cgroupInode, contents map[string]kernfs.Inode) {
	cpuacctCG := &cpuacctCgroup{cg}
	contents["cpuacct.stat"] = c.fs.newControllerFile(ctx, creds, &cpuacctStatData{cpuacctCG})
	contents["cpuacct.usage"] = c.fs.newControllerFile(ctx, creds, &cpuacctUsageData{cpuacctCG})
	contents["cpuacct.usage_user"] = c.fs.newControllerFile(ctx, creds, &cpuacctUsageUserData{cpuacctCG})
	contents["cpuacct.usage_sys"] = c.fs.newControllerFile(ctx, creds, &cpuacctUsageSysData{cpuacctCG})
}

// +stateify savable
type cpuacctCgroup struct {
	*cgroupInode
}

func (c *cpuacctCgroup) collectCPUStats() usage.CPUStats {
	var cs usage.CPUStats
	c.fs.tasksMu.RLock()
	// Note: This isn't very accurate, since the tasks are potentially
	// still running as we accumulate their stats.
	for t := range c.ts {
		cs.Accumulate(t.CPUStats())
	}
	c.fs.tasksMu.RUnlock()
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
