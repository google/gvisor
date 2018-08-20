// Copyright 2018 Google Inc.
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
	"io"

	"gvisor.googlesource.com/gvisor/pkg/sentry/context"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs/ramfs"
	"gvisor.googlesource.com/gvisor/pkg/sentry/kernel"
	"gvisor.googlesource.com/gvisor/pkg/sentry/usermem"
	"gvisor.googlesource.com/gvisor/pkg/syserror"
)

// +stateify savable
type cpunum struct {
	ramfs.Entry
}

func (c *cpunum) DeprecatedPreadv(ctx context.Context, dst usermem.IOSequence, offset int64) (int64, error) {
	if offset < 0 {
		return 0, syserror.EINVAL
	}

	k := kernel.KernelFromContext(ctx)
	if k == nil {
		return 0, io.EOF
	}

	str := []byte(fmt.Sprintf("0-%d\n", k.ApplicationCores()-1))
	if offset >= int64(len(str)) {
		return 0, io.EOF
	}

	n, err := dst.CopyOut(ctx, str[offset:])
	return int64(n), err
}

func newPossible(ctx context.Context, msrc *fs.MountSource) *fs.Inode {
	c := &cpunum{}
	c.InitEntry(ctx, fs.RootOwner, fs.FilePermsFromMode(0444))
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
