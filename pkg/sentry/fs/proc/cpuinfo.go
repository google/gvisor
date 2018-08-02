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

package proc

import (
	"io"

	"gvisor.googlesource.com/gvisor/pkg/sentry/context"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs/ramfs"
	"gvisor.googlesource.com/gvisor/pkg/sentry/kernel"
	"gvisor.googlesource.com/gvisor/pkg/sentry/usermem"
)

// cpuinfo is a file describing the CPU capabilities.
//
// Presently cpuinfo never changes, so it doesn't need to be a SeqFile.
//
// +stateify savable
type cpuinfo struct {
	ramfs.Entry

	// k is the system kernel.
	k *kernel.Kernel
}

// DeprecatedPreadv implements fs.InodeOperations.DeprecatedPreadv.
func (c *cpuinfo) DeprecatedPreadv(ctx context.Context, dst usermem.IOSequence, offset int64) (int64, error) {
	features := c.k.FeatureSet()
	if features == nil {
		// Kernel is always initialized with a FeatureSet.
		panic("cpuinfo read with nil FeatureSet")
	}

	contents := make([]byte, 0, 1024)
	for i, max := uint(0), c.k.ApplicationCores(); i < max; i++ {
		contents = append(contents, []byte(features.CPUInfo(i))...)
	}
	if offset >= int64(len(contents)) {
		return 0, io.EOF
	}

	n, err := dst.CopyOut(ctx, contents[offset:])
	return int64(n), err
}

func (p *proc) newCPUInfo(ctx context.Context, msrc *fs.MountSource) *fs.Inode {
	f := &cpuinfo{
		k: p.k,
	}
	f.InitEntry(ctx, fs.RootOwner, fs.FilePermsFromMode(0444))

	return newFile(f, msrc, fs.SpecialFile, nil)
}
