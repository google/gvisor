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
	"fmt"

	"gvisor.dev/gvisor/pkg/sentry/context"
	"gvisor.dev/gvisor/pkg/sentry/fs"
)

func newCGroupInode(ctx context.Context, msrc *fs.MountSource, cgroupControllers map[string]string) *fs.Inode {
	// From man 7 cgroups: "For each cgroup hierarchy of which the process
	// is a member, there is one entry containing three colon-separated
	// fields: hierarchy-ID:controller-list:cgroup-path"

	// The hierarchy ids must be positive integers (for cgroup v1), but the
	// exact number does not matter, so long as they are unique. We can
	// just use a counter, but since linux sorts this file in descending
	// order, we must count down to perserve this behavior.
	i := len(cgroupControllers)
	var data string
	for name, dir := range cgroupControllers {
		data += fmt.Sprintf("%d:%s:%s\n", i, name, dir)
		i--
	}

	return newStaticProcInode(ctx, msrc, []byte(data))
}
