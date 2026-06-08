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
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/usage"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/usermem"
)

// +stateify savable
type memory struct {
	c        *cgroup
	parent   *memory
	id       uint32
	detached atomicbitops.Bool

	// maxBytes is the memory limit representing the memory.max limit.
	// +checkatomic
	maxBytes atomicbitops.Int64
	// highBytes is the memory limit representing the memory.high limit.
	// +checkatomic
	highBytes atomicbitops.Int64
}

// canEnter implements controller.canEnter.
func (m *memory) canEnter(ctx context.Context, t *kernel.Task) bool { return true }

// cancelEnter implements controller.cancelEnter.
func (m *memory) cancelEnter(ctx context.Context, t *kernel.Task) {}

// enter implements controller.enter.
func (m *memory) enter(ctx context.Context, t *kernel.Task) {
	t.SetMemCgID(m.id)
}

// exit implements controller.exit.
func (m *memory) exit(ctx context.Context, t *kernel.Task) {
	t.SetMemCgID(0)
}

// canAttach implements controller.canAttach.
func (m *memory) canAttach(ctx context.Context, actx *attachCtx) bool { return true }

// cancelAttach implements controller.cancelAttach.
func (m *memory) cancelAttach(ctx context.Context, actx *attachCtx) {}

// attach implements controller.attach.
func (m *memory) attach(ctx context.Context, actx *attachCtx) {
	for t := range actx.tasks {
		t.SetMemCgID(m.id)
	}
}

// interfaceFiles implements controller.interfaceFiles.
func (m *memory) interfaceFiles() []interfaceFile {
	return []interfaceFile{
		{name: "memory.events", source: &memoryEvents{m: m}, perm: 0444},
		{name: "memory.current", source: &memoryCurrent{m: m}, perm: 0444},
		{name: "memory.max", source: &memoryMax{m: m}, perm: 0644},
		{name: "memory.high", source: &memoryHigh{m: m}, perm: 0644},
	}
}

// interfaceFileNames implements controller.interfaceFileNames.
func (m *memory) interfaceFileNames() []string {
	return []string{"memory.events", "memory.current", "memory.max", "memory.high"}
}

// +stateify savable
type memoryEvents struct {
	m *memory
}

// Generate implements vfs.DynamicBytesSource.Generate.
func (me *memoryEvents) Generate(ctx context.Context, buf *bytes.Buffer) error {
	buf.WriteString("low 0\nhigh 0\nmax 0\noom 0\noom_kill 0\noom_group_kill 0\nsock_throttled 0\n")
	return nil
}

// +stateify savable
type memoryCurrent struct {
	m *memory
}

// Collects all the memory cgroup ids under the given cgroup.
// +checklocksread:c.fs.treeMu
func (mc *memoryCurrent) collectMemCgIDs(c *cgroup, memCgIDs map[uint32]struct{}) {
	// Add ourselves.
	if mem := c.ctrls[kernel.Cgroup2Memory]; mem != nil {
		memCgIDs[mem.(*memory).id] = struct{}{}
	}
	// Add our children.
	for child := range c.children {
		mc.collectMemCgIDs(child, memCgIDs) // +checklocksforce: c.fs.treeMu is locked
	}
}

// Returns the memory usage for all cgroup ids in memCgIDs.
func getUsage(k *kernel.Kernel, memCgIDs map[uint32]struct{}) uint64 {
	k.MemoryFile().UpdateUsage(memCgIDs)
	var totalBytes uint64
	for id := range memCgIDs {
		_, bytes := usage.MemoryAccounting.CopyPerCg(id)
		totalBytes += bytes
	}
	return totalBytes
}

// Generate implements vfs.DynamicBytesSource.Generate.
func (mc *memoryCurrent) Generate(ctx context.Context, buf *bytes.Buffer) error {
	k := kernel.KernelFromContext(ctx)

	memCgIDs := make(map[uint32]struct{})
	mc.m.c.fs.treeMu.RLock()
	mc.collectMemCgIDs(mc.m.c, memCgIDs)
	mc.m.c.fs.treeMu.RUnlock()

	totalBytes := getUsage(k, memCgIDs)
	fmt.Fprintf(buf, "%d\n", totalBytes)
	return nil
}

// +stateify savable
type memoryMax struct {
	m *memory
}

// Generate implements vfs.DynamicBytesSource.Generate.
func (mm *memoryMax) Generate(ctx context.Context, buf *bytes.Buffer) error {
	val := mm.m.maxBytes.Load()
	if val == math.MaxInt64 {
		buf.WriteString("max\n")
	} else {
		fmt.Fprintf(buf, "%d\n", val)
	}
	return nil
}

// Write implements vfs.WritableDynamicBytesSource.Write.
//
// Note: Although memory.max is writable and remembers the value, nothing is enforced.
func (mm *memoryMax) Write(ctx context.Context, _ *vfs.FileDescription, src usermem.IOSequence, offset int64) (int64, error) {
	if src.NumBytes() > 1024 {
		return 0, linuxerr.EINVAL
	}
	buf := make([]byte, src.NumBytes())
	if _, err := src.CopyIn(ctx, buf); err != nil {
		return 0, err
	}
	str := strings.TrimSpace(string(buf))
	val, err := parseMemoryLimit(str)
	if err != nil {
		return 0, linuxerr.EINVAL
	}
	mm.m.maxBytes.Store(val)
	return int64(len(buf)), nil
}

// +stateify savable
type memoryHigh struct {
	m *memory
}

// Generate implements vfs.DynamicBytesSource.Generate.
func (mh *memoryHigh) Generate(ctx context.Context, buf *bytes.Buffer) error {
	val := mh.m.highBytes.Load()
	if val == math.MaxInt64 {
		buf.WriteString("max\n")
	} else {
		fmt.Fprintf(buf, "%d\n", val)
	}
	return nil
}

// Write implements vfs.WritableDynamicBytesSource.Write.
//
// Note: Although memory.high is writable and remembers the value, nothing is enforced.
func (mh *memoryHigh) Write(ctx context.Context, _ *vfs.FileDescription, src usermem.IOSequence, offset int64) (int64, error) {
	if src.NumBytes() > 1024 {
		return 0, linuxerr.EINVAL
	}
	buf := make([]byte, src.NumBytes())
	if _, err := src.CopyIn(ctx, buf); err != nil {
		return 0, err
	}
	str := strings.TrimSpace(string(buf))
	val, err := parseMemoryLimit(str)
	if err != nil {
		return 0, linuxerr.EINVAL
	}
	mh.m.highBytes.Store(val)
	return int64(len(buf)), nil
}

// detach implements controller.detach.
func (m *memory) detach() {
	m.detached.Store(true)
}

// isActive implements controller.isActive.
func (m *memory) isActive() bool {
	return !m.detached.Load()
}

func parseMemoryLimit(str string) (int64, error) {
	if str == "max" {
		return math.MaxInt64, nil
	}
	if len(str) == 0 {
		return 0, fmt.Errorf("empty memory limit")
	}

	idx := -1
	for i := 0; i < len(str); i++ {
		c := str[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') {
			idx = i
			break
		}
	}

	var numStr, suffix string
	if idx == -1 {
		numStr = str
	} else {
		numStr = str[:idx]
		suffix = strings.ToLower(str[idx:])
	}

	val, err := strconv.ParseInt(numStr, 10, 64)
	if err != nil {
		return 0, err
	}
	if val < 0 {
		return 0, fmt.Errorf("negative memory limit: %d", val)
	}

	result := val
	if suffix != "" {
		var shift uint
		switch {
		case strings.HasPrefix(suffix, "k"):
			shift = 10
		case strings.HasPrefix(suffix, "m"):
			shift = 20
		case strings.HasPrefix(suffix, "g"):
			shift = 30
		case strings.HasPrefix(suffix, "t"):
			shift = 40
		case strings.HasPrefix(suffix, "p"):
			shift = 50
		case strings.HasPrefix(suffix, "e"):
			shift = 60
		default:
			return 0, fmt.Errorf("invalid suffix %q", suffix)
		}

		rem := suffix[1:]
		if rem != "" && rem != "b" && rem != "ib" {
			return 0, fmt.Errorf("invalid suffix configuration %q", suffix)
		}

		if val > (math.MaxInt64 >> shift) {
			return 0, fmt.Errorf("value overflowed")
		}
		result = val << shift
	}

	if result != math.MaxInt64 {
		result = result &^ int64(hostarch.PageSize-1)
	}
	return result, nil
}
