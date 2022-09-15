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
	"gvisor.dev/gvisor/pkg/atomicbitops"
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
	cfsPeriod atomicbitops.Int64
	cfsQuota  atomicbitops.Int64

	// CPU shares, values should be (num core * 1024).
	shares atomicbitops.Int64
}

var _ controller = (*cpuController)(nil)

func newCPUController(fs *filesystem, defaults map[string]int64) *cpuController {
	// Default values for controller parameters from Linux.
	c := &cpuController{
		cfsPeriod: atomicbitops.FromInt64(100000),
		cfsQuota:  atomicbitops.FromInt64(-1),
		shares:    atomicbitops.FromInt64(1024),
	}

	if val, ok := defaults["cpu.cfs_period_us"]; ok {
		c.cfsPeriod = atomicbitops.FromInt64(val)
		delete(defaults, "cpu.cfs_period_us")
	}
	if val, ok := defaults["cpu.cfs_quota_us"]; ok {
		c.cfsQuota = atomicbitops.FromInt64(val)
		delete(defaults, "cpu.cfs_quota_us")
	}
	if val, ok := defaults["cpu.shares"]; ok {
		c.shares = atomicbitops.FromInt64(val)
		delete(defaults, "cpu.shares")
	}

	c.controllerCommon.init(kernel.CgroupControllerCPU, fs)
	return c
}

// Clone implements controller.Clone.
func (c *cpuController) Clone() controller {
	new := &cpuController{
		cfsPeriod: atomicbitops.FromInt64(c.cfsPeriod.Load()),
		cfsQuota:  atomicbitops.FromInt64(c.cfsQuota.Load()),
		shares:    atomicbitops.FromInt64(c.shares.Load()),
	}
	new.controllerCommon.cloneFromParent(c)
	return new
}

// AddControlFiles implements controller.AddControlFiles.
func (c *cpuController) AddControlFiles(ctx context.Context, creds *auth.Credentials, _ *cgroupInode, contents map[string]kernfs.Inode) {
	contents["cpu.cfs_period_us"] = c.fs.newStubControllerFile(ctx, creds, &c.cfsPeriod, true)
	contents["cpu.cfs_quota_us"] = c.fs.newStubControllerFile(ctx, creds, &c.cfsQuota, true)
	contents["cpu.shares"] = c.fs.newStubControllerFile(ctx, creds, &c.shares, true)
}
