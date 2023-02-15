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
	"sync/atomic"

	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/kernfs"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
)

// +stateify savable
type cpuController struct {
	controllerCommon
	controllerStateless
	controllerNoResource

	// CFS bandwidth control parameters, values in microseconds.
	cfsPeriod atomic.Int64
	cfsQuota  atomic.Int64

	// CPU shares, values should be (num core * 1024).
	shares atomic.Int64
}

var _ controller = (*cpuController)(nil)

func newCPUController(fs *filesystem, defaults map[string]int64) *cpuController {
	// Default values for controller parameters from Linux.
	c := &cpuController{}
	c.cfsPeriod.Store(100000)
	c.cfsQuota.Store(-1)
	c.shares.Store(1024)

	if val, ok := defaults["cpu.cfs_period_us"]; ok {
		c.cfsPeriod.Store(val)
		delete(defaults, "cpu.cfs_period_us")
	}
	if val, ok := defaults["cpu.cfs_quota_us"]; ok {
		c.cfsQuota.Store(val)
		delete(defaults, "cpu.cfs_quota_us")
	}
	if val, ok := defaults["cpu.shares"]; ok {
		c.shares.Store(val)
		delete(defaults, "cpu.shares")
	}

	c.controllerCommon.init(kernel.CgroupControllerCPU, fs)
	return c
}

// Clone implements controller.Clone.
func (c *cpuController) Clone() controller {
	other := &cpuController{}
	other.cfsPeriod.Store(c.cfsPeriod.Load())
	other.cfsQuota.Store(c.cfsQuota.Load())
	other.shares.Store(c.shares.Load())
	other.controllerCommon.cloneFromParent(c)
	return other
}

// AddControlFiles implements controller.AddControlFiles.
func (c *cpuController) AddControlFiles(ctx context.Context, creds *auth.Credentials, _ *cgroupInode, contents map[string]kernfs.Inode) {
	contents["cpu.cfs_period_us"] = c.fs.newStubControllerFile(ctx, creds, &c.cfsPeriod, true)
	contents["cpu.cfs_quota_us"] = c.fs.newStubControllerFile(ctx, creds, &c.cfsQuota, true)
	contents["cpu.shares"] = c.fs.newStubControllerFile(ctx, creds, &c.shares, true)
}
