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

	"gvisor.dev/gvisor/pkg/bitmap"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/kernfs"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/usermem"
)

// +stateify savable
type cpusetController struct {
	controllerCommon

	maxCpus uint32
	maxMems uint32

	mu sync.Mutex `state:"nosave"`

	cpus *bitmap.Bitmap
	mems *bitmap.Bitmap
}

var _ controller = (*cpusetController)(nil)

func newCPUSetController(k *kernel.Kernel, fs *filesystem) *cpusetController {
	cores := uint32(k.ApplicationCores())
	cpus := bitmap.New(cores)
	cpus.FlipRange(0, cores)
	mems := bitmap.New(1)
	mems.FlipRange(0, 1)
	c := &cpusetController{
		cpus:    &cpus,
		mems:    &mems,
		maxCpus: uint32(k.ApplicationCores()),
		maxMems: 1, // We always report a single NUMA node.
	}
	c.controllerCommon.init(controllerCPUSet, fs)
	return c
}

// AddControlFiles implements controller.AddControlFiles.
func (c *cpusetController) AddControlFiles(ctx context.Context, creds *auth.Credentials, _ *cgroupInode, contents map[string]kernfs.Inode) {
	contents["cpuset.cpus"] = c.fs.newControllerWritableFile(ctx, creds, &cpusData{c: c})
	contents["cpuset.mems"] = c.fs.newControllerWritableFile(ctx, creds, &memsData{c: c})
}

// +stateify savable
type cpusData struct {
	c *cpusetController
}

// Generate implements vfs.DynamicBytesSource.Generate.
func (d *cpusData) Generate(ctx context.Context, buf *bytes.Buffer) error {
	d.c.mu.Lock()
	defer d.c.mu.Unlock()
	fmt.Fprintf(buf, "%s\n", formatBitmap(d.c.cpus))
	return nil
}

// Write implements vfs.WritableDynamicBytesSource.Write.
func (d *cpusData) Write(ctx context.Context, src usermem.IOSequence, offset int64) (int64, error) {
	src = src.DropFirst64(offset)
	if src.NumBytes() > hostarch.PageSize {
		return 0, linuxerr.EINVAL
	}

	t := kernel.TaskFromContext(ctx)
	buf := t.CopyScratchBuffer(hostarch.PageSize)
	n, err := src.CopyIn(ctx, buf)
	if err != nil {
		return 0, err
	}
	buf = buf[:n]

	b, err := parseBitmap(string(buf), d.c.maxCpus)
	if err != nil {
		log.Warningf("cgroupfs cpuset controller: Failed to parse bitmap: %v", err)
		return 0, linuxerr.EINVAL
	}

	if got, want := b.Maximum(), d.c.maxCpus; got > want {
		log.Warningf("cgroupfs cpuset controller: Attempted to specify cpuset.cpus beyond highest available cpu: got %d, want %d", got, want)
		return 0, linuxerr.EINVAL
	}

	d.c.mu.Lock()
	defer d.c.mu.Unlock()
	d.c.cpus = b
	return int64(n), nil
}

// +stateify savable
type memsData struct {
	c *cpusetController
}

// Generate implements vfs.DynamicBytesSource.Generate.
func (d *memsData) Generate(ctx context.Context, buf *bytes.Buffer) error {
	d.c.mu.Lock()
	defer d.c.mu.Unlock()
	fmt.Fprintf(buf, "%s\n", formatBitmap(d.c.mems))
	return nil
}

// Write implements vfs.WritableDynamicBytesSource.Write.
func (d *memsData) Write(ctx context.Context, src usermem.IOSequence, offset int64) (int64, error) {
	src = src.DropFirst64(offset)
	if src.NumBytes() > hostarch.PageSize {
		return 0, linuxerr.EINVAL
	}

	t := kernel.TaskFromContext(ctx)
	buf := t.CopyScratchBuffer(hostarch.PageSize)
	n, err := src.CopyIn(ctx, buf)
	if err != nil {
		return 0, err
	}
	buf = buf[:n]

	b, err := parseBitmap(string(buf), d.c.maxMems)
	if err != nil {
		log.Warningf("cgroupfs cpuset controller: Failed to parse bitmap: %v", err)
		return 0, linuxerr.EINVAL
	}

	if got, want := b.Maximum(), d.c.maxMems; got > want {
		log.Warningf("cgroupfs cpuset controller: Attempted to specify cpuset.mems beyond highest available node: got %d, want %d", got, want)
		return 0, linuxerr.EINVAL
	}

	d.c.mu.Lock()
	defer d.c.mu.Unlock()
	d.c.mems = b
	return int64(n), nil
}
