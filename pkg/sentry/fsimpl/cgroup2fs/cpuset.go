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

	"gvisor.dev/gvisor/pkg/atomicbitops"
	"gvisor.dev/gvisor/pkg/bitmap"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/usermem"
)

// +stateify savable
type cpuset struct {
	c        *cgroup
	parent   *cpuset
	detached atomicbitops.Bool

	mu sync.Mutex `state:"nosave"`

	cpus *bitmap.Bitmap
	mems *bitmap.Bitmap
}

// canEnter implements controller.canEnter.
func (cs *cpuset) canEnter(ctx context.Context, t *kernel.Task) bool { return true }

// cancelEnter implements controller.cancelEnter.
func (cs *cpuset) cancelEnter(ctx context.Context, t *kernel.Task) {}

// enter implements controller.enter.
func (cs *cpuset) enter(ctx context.Context, t *kernel.Task) {}

// exit implements controller.exit.
func (cs *cpuset) exit(ctx context.Context, t *kernel.Task) {}

// canAttach implements controller.canAttach.
func (cs *cpuset) canAttach(ctx context.Context, actx *attachCtx) bool { return true }

// cancelAttach implements controller.cancelAttach.
func (cs *cpuset) cancelAttach(ctx context.Context, actx *attachCtx) {}

// attach implements controller.attach.
func (cs *cpuset) attach(ctx context.Context, actx *attachCtx) {}

// interfaceFiles implements controller.interfaceFiles.
func (cs *cpuset) interfaceFiles() []interfaceFile {
	return []interfaceFile{
		{name: "cpuset.cpus", source: &cpusetCpus{cs: cs}, perm: 0644},
		{name: "cpuset.mems", source: &cpusetMems{cs: cs}, perm: 0644},
	}
}

// interfaceFileNames implements controller.interfaceFileNames.
func (cs *cpuset) interfaceFileNames() []string {
	return []string{"cpuset.cpus", "cpuset.mems"}
}

// +stateify savable
type cpusetCpus struct {
	cs *cpuset
}

// Generate implements vfs.DynamicBytesSource.Generate.
func (cc *cpusetCpus) Generate(ctx context.Context, buf *bytes.Buffer) error {
	cc.cs.mu.Lock()
	defer cc.cs.mu.Unlock()
	if cc.cs.cpus != nil {
		fmt.Fprintf(buf, "%s\n", bitmap.FormatList(cc.cs.cpus))
	} else {
		buf.WriteString("\n")
	}
	return nil
}

// Write implements vfs.WritableDynamicBytesSource.Write.
func (cc *cpusetCpus) Write(ctx context.Context, _ *vfs.FileDescription, src usermem.IOSequence, offset int64) (int64, error) {
	if src.NumBytes() > hostarch.PageSize {
		return 0, linuxerr.EINVAL
	}

	k := kernel.KernelFromContext(ctx)
	if k == nil {
		return 0, linuxerr.EINVAL
	}
	maxCpus := uint32(k.ApplicationCores())

	buf := make([]byte, src.NumBytes())
	n, err := src.CopyIn(ctx, buf)
	if err != nil {
		return 0, err
	}
	buf = buf[:n]

	b, err := bitmap.ParseList(string(buf), maxCpus)
	if err != nil {
		return 0, linuxerr.EINVAL
	}
	if got, want := b.Maximum(), maxCpus; got > want {
		return 0, linuxerr.EINVAL
	}

	cc.cs.mu.Lock()
	defer cc.cs.mu.Unlock()
	cc.cs.cpus = b
	return int64(n), nil
}

// +stateify savable
type cpusetMems struct {
	cs *cpuset
}

// Generate implements vfs.DynamicBytesSource.Generate.
func (cm *cpusetMems) Generate(ctx context.Context, buf *bytes.Buffer) error {
	cm.cs.mu.Lock()
	defer cm.cs.mu.Unlock()
	if cm.cs.mems != nil {
		fmt.Fprintf(buf, "%s\n", bitmap.FormatList(cm.cs.mems))
	} else {
		buf.WriteString("\n")
	}
	return nil
}

// Write implements vfs.WritableDynamicBytesSource.Write.
func (cm *cpusetMems) Write(ctx context.Context, _ *vfs.FileDescription, src usermem.IOSequence, offset int64) (int64, error) {
	if src.NumBytes() > hostarch.PageSize {
		return 0, linuxerr.EINVAL
	}

	maxMems := uint32(1)

	buf := make([]byte, src.NumBytes())
	n, err := src.CopyIn(ctx, buf)
	if err != nil {
		return 0, err
	}
	buf = buf[:n]

	b, err := bitmap.ParseList(string(buf), maxMems)
	if err != nil {
		return 0, linuxerr.EINVAL
	}
	if got, want := b.Maximum(), maxMems; got > want {
		return 0, linuxerr.EINVAL
	}

	cm.cs.mu.Lock()
	defer cm.cs.mu.Unlock()
	cm.cs.mems = b
	return int64(n), nil
}

// detach implements controller.detach.
func (cs *cpuset) detach() {
	cs.detached.Store(true)
}

// isActive implements controller.isActive.
func (cs *cpuset) isActive() bool {
	return !cs.detached.Load()
}
