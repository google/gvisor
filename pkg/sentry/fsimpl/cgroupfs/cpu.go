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
	"fmt"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/kernfs"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
)

// +stateify savable
type cpuController struct {
	controllerCommon

	// CFS bandwidth control parameters, values in microseconds.
	cfsPeriod uint64
	cfsQuota  int64

	// CPU shares, values should be (num core * 1024).
	shares uint64
}

var _ controller = (*cpuController)(nil)

func newCPUController(fs *filesystem) *cpuController {
	// Default values for controller parameters from Linux.
	c := &cpuController{
		cfsPeriod: 100000,
		cfsQuota:  -1,
		shares:    1024,
	}
	c.controllerCommon.init(controllerCPU, fs)
	return c
}

// AddControlFiles implements controller.AddControlFiles.
func (c *cpuController) AddControlFiles(ctx context.Context, creds *auth.Credentials, _ *cgroupInode, contents map[string]kernfs.Inode) {
	contents["cpu.cfs_period_us"] = c.fs.newStaticControllerFile(ctx, creds, linux.FileMode(0644), fmt.Sprintf("%d\n", c.cfsPeriod))
	contents["cpu.cfs_quota_us"] = c.fs.newStaticControllerFile(ctx, creds, linux.FileMode(0644), fmt.Sprintf("%d\n", c.cfsQuota))
	contents["cpu.shares"] = c.fs.newStaticControllerFile(ctx, creds, linux.FileMode(0644), fmt.Sprintf("%d\n", c.shares))
}
