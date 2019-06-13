// Copyright 2018 The gVisor Authors.
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

package sys

import (
	"fmt"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/sentry/context"
	"gvisor.dev/gvisor/pkg/sentry/fs"
	"gvisor.dev/gvisor/pkg/sentry/fs/fsutil"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
)

// +stateify savable
type cpunum struct {
	fsutil.InodeGenericChecker       `state:"nosave"`
	fsutil.InodeNoExtendedAttributes `state:"nosave"`
	fsutil.InodeNoopRelease          `state:"nosave"`
	fsutil.InodeNoopWriteOut         `state:"nosave"`
	fsutil.InodeNotAllocatable       `state:"nosave"`
	fsutil.InodeNotDirectory         `state:"nosave"`
	fsutil.InodeNotMappable          `state:"nosave"`
	fsutil.InodeNotSocket            `state:"nosave"`
	fsutil.InodeNotSymlink           `state:"nosave"`
	fsutil.InodeNotTruncatable       `state:"nosave"`
	fsutil.InodeNotVirtual           `state:"nosave"`

	fsutil.InodeSimpleAttributes
	fsutil.InodeStaticFileGetter
}

var _ fs.InodeOperations = (*cpunum)(nil)

func newPossible(ctx context.Context, msrc *fs.MountSource) *fs.Inode {
	var maxCore uint
	k := kernel.KernelFromContext(ctx)
	if k != nil {
		maxCore = k.ApplicationCores() - 1
	}
	contents := []byte(fmt.Sprintf("0-%d\n", maxCore))

	c := &cpunum{
		InodeSimpleAttributes: fsutil.NewInodeSimpleAttributes(ctx, fs.RootOwner, fs.FilePermsFromMode(0444), linux.SYSFS_MAGIC),
		InodeStaticFileGetter: fsutil.InodeStaticFileGetter{
			Contents: contents,
		},
	}
	return newFile(c, msrc)
}

func newCPU(ctx context.Context, msrc *fs.MountSource) *fs.Inode {
	m := map[string]*fs.Inode{
		"online":   newPossible(ctx, msrc),
		"possible": newPossible(ctx, msrc),
		"present":  newPossible(ctx, msrc),
	}

	// Add directories for each of the cpus.
	if k := kernel.KernelFromContext(ctx); k != nil {
		for i := 0; uint(i) < k.ApplicationCores(); i++ {
			m[fmt.Sprintf("cpu%d", i)] = newDir(ctx, msrc, nil)
		}
	}

	return newDir(ctx, msrc, m)
}

func newSystemDir(ctx context.Context, msrc *fs.MountSource) *fs.Inode {
	return newDir(ctx, msrc, map[string]*fs.Inode{
		"cpu": newCPU(ctx, msrc),
	})
}

func newDevicesDir(ctx context.Context, msrc *fs.MountSource) *fs.Inode {
	return newDir(ctx, msrc, map[string]*fs.Inode{
		"system": newSystemDir(ctx, msrc),
	})
}
