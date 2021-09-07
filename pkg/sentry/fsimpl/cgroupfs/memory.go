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
	"math"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/kernfs"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/usage"
)

// +stateify savable
type memoryController struct {
	controllerCommon

	limitBytes            int64
	softLimitBytes        int64
	moveChargeAtImmigrate int64
}

var _ controller = (*memoryController)(nil)

func newMemoryController(fs *filesystem, defaults map[string]int64) *memoryController {
	c := &memoryController{
		// Linux sets these limits to (PAGE_COUNTER_MAX * PAGE_SIZE) by default,
		// which is ~ 2**63 on a 64-bit system. So essentially, inifinity. The
		// exact value isn't very important.

		limitBytes:     math.MaxInt64,
		softLimitBytes: math.MaxInt64,
	}

	consumeDefault := func(name string, valPtr *int64) {
		if val, ok := defaults[name]; ok {
			*valPtr = val
			delete(defaults, name)
		}
	}

	consumeDefault("memory.limit_in_bytes", &c.limitBytes)
	consumeDefault("memory.soft_limit_in_bytes", &c.softLimitBytes)
	consumeDefault("memory.move_charge_at_immigrate", &c.moveChargeAtImmigrate)

	c.controllerCommon.init(controllerMemory, fs)
	return c
}

// AddControlFiles implements controller.AddControlFiles.
func (c *memoryController) AddControlFiles(ctx context.Context, creds *auth.Credentials, _ *cgroupInode, contents map[string]kernfs.Inode) {
	contents["memory.usage_in_bytes"] = c.fs.newControllerFile(ctx, creds, &memoryUsageInBytesData{})
	contents["memory.limit_in_bytes"] = c.fs.newStaticControllerFile(ctx, creds, linux.FileMode(0644), fmt.Sprintf("%d\n", c.limitBytes))
	contents["memory.soft_limit_in_bytes"] = c.fs.newStaticControllerFile(ctx, creds, linux.FileMode(0644), fmt.Sprintf("%d\n", c.softLimitBytes))
	contents["memory.move_charge_at_immigrate"] = c.fs.newStaticControllerFile(ctx, creds, linux.FileMode(0644), fmt.Sprintf("%d\n", c.moveChargeAtImmigrate))
}

// +stateify savable
type memoryUsageInBytesData struct{}

// Generate implements vfs.DynamicBytesSource.Generate.
func (d *memoryUsageInBytesData) Generate(ctx context.Context, buf *bytes.Buffer) error {
	// TODO(b/183151557): This is a giant hack, we're using system-wide
	// accounting since we know there is only one cgroup.
	k := kernel.KernelFromContext(ctx)
	mf := k.MemoryFile()
	mf.UpdateUsage()
	_, totalBytes := usage.MemoryAccounting.Copy()

	fmt.Fprintf(buf, "%d\n", totalBytes)
	return nil
}
