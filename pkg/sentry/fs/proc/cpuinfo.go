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

package proc

import (
	"gvisor.dev/gvisor/pkg/sentry/context"
	"gvisor.dev/gvisor/pkg/sentry/fs"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
)

func newCPUInfo(ctx context.Context, msrc *fs.MountSource) *fs.Inode {
	k := kernel.KernelFromContext(ctx)
	features := k.FeatureSet()
	if features == nil {
		// Kernel is always initialized with a FeatureSet.
		panic("cpuinfo read with nil FeatureSet")
	}
	contents := make([]byte, 0, 1024)
	for i, max := uint(0), k.ApplicationCores(); i < max; i++ {
		contents = append(contents, []byte(features.CPUInfo(i))...)
	}
	return newStaticProcInode(ctx, msrc, contents)
}
