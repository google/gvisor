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
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/usermem"
)

// +stateify savable
type cpu struct {
	c        *cgroup
	parent   *cpu
	detached atomicbitops.Bool

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
func (c *cpu) canEnter(ctx context.Context, t *kernel.Task) bool { return true }

// cancelEnter implements controller.cancelEnter.
func (c *cpu) cancelEnter(ctx context.Context, t *kernel.Task) {}

// enter implements controller.enter.
func (c *cpu) enter(ctx context.Context, t *kernel.Task) {}

// exit implements controller.exit.
func (c *cpu) exit(ctx context.Context, t *kernel.Task) {}

// canAttach implements controller.canAttach.
func (c *cpu) canAttach(ctx context.Context, actx *attachCtx) bool { return true }

// cancelAttach implements controller.cancelAttach.
func (c *cpu) cancelAttach(ctx context.Context, actx *attachCtx) {}

// attach implements controller.attach.
func (c *cpu) attach(ctx context.Context, actx *attachCtx) {}

// interfaceFiles implements controller.interfaceFiles.
func (c *cpu) interfaceFiles() []interfaceFile {
	return []interfaceFile{
		{name: "cpu.stat", source: &cpuStat{c: c}, perm: 0444, showAtRoot: true},
		{name: "cpu.max", source: &cpuMax{c: c}, perm: 0644},
		{name: "cpu.weight", source: &cpuWeight{c: c}, perm: 0644},
	}
}

// interfaceFileNames implements controller.interfaceFileNames.
func (c *cpu) interfaceFileNames() []string {
	return []string{"cpu.stat", "cpu.max", "cpu.weight"}
}

// +stateify savable
type cpuStat struct {
	c *cpu
}

// Generate implements vfs.DynamicBytesSource.Generate.
func (c *cpuStat) Generate(ctx context.Context, buf *bytes.Buffer) error {
	buf.WriteString("usage_usec 0\nuser_usec 0\nsystem_usec 0\nnice_usec 0\nnr_periods 0\nnr_throttled 0\nthrottled_usec 0\nnr_bursts 0\nburst_usec 0\n")
	return nil
}

// +stateify savable
type cpuMax struct {
	c *cpu
}

// Generate implements vfs.DynamicBytesSource.Generate.
func (c *cpuMax) Generate(ctx context.Context, buf *bytes.Buffer) error {
	quota := c.c.maxUSec.Load()
	period := c.c.periodUSec.Load()
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
func (c *cpuMax) Write(ctx context.Context, _ *vfs.FileDescription, src usermem.IOSequence, offset int64) (int64, error) {
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
		period = c.c.periodUSec.Load()
	}

	c.c.maxUSec.Store(quota)
	c.c.periodUSec.Store(period)
	return int64(len(buf)), nil
}

// +stateify savable
type cpuWeight struct {
	c *cpu
}

// Generate implements vfs.DynamicBytesSource.Generate.
func (c *cpuWeight) Generate(ctx context.Context, buf *bytes.Buffer) error {
	fmt.Fprintf(buf, "%d\n", c.c.weight.Load())
	return nil
}

// Write implements vfs.WritableDynamicBytesSource.Write.
//
// Note: Although cpu.weight is writable and remembers the value, nothing is enforced.
func (c *cpuWeight) Write(ctx context.Context, _ *vfs.FileDescription, src usermem.IOSequence, offset int64) (int64, error) {
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
	c.c.weight.Store(val)
	return int64(len(buf)), nil
}

// detach implements controller.detach.
func (c *cpu) detach() {
	c.detached.Store(true)
}

// isActive implements controller.isActive.
func (c *cpu) isActive() bool {
	return !c.detached.Load()
}
