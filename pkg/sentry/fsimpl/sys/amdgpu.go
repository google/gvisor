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

package sys

import (
	"fmt"
	"path"
	"strings"

	"gvisor.dev/gvisor/pkg/amdgpu"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/rdma"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
)

// newAMDGPUSysfs builds the AMD GPU sysfs subtrees from snap.
func (fs *filesystem) newAMDGPUSysfs(ctx context.Context, creds *auth.Credentials, snap *amdgpu.Snapshot) (*sysfsDirs, error) {
	root := newDirTree()
	parent := func(p string) (*dirTree, string, error) {
		if !strings.HasPrefix(p, "devices/") && !strings.HasPrefix(p, "class/") && !strings.HasPrefix(p, "bus/pci/") && !strings.HasPrefix(p, "dev/char/") {
			return nil, "", fmt.Errorf("unexpected AMD GPU sysfs path %q", p)
		}
		for _, part := range strings.Split(p, "/") {
			if !rdma.SafeName(part) {
				return nil, "", fmt.Errorf("AMD GPU sysfs path %q contains unsafe component %q", p, part)
			}
		}
		return root.get(path.Dir(p)), path.Base(p), nil
	}
	for _, p := range snap.Dirs {
		dir, name, err := parent(p)
		if err != nil {
			return nil, err
		}
		dir.get(name)
	}
	for p, data := range snap.Files {
		dir, name, err := parent(p)
		if err != nil {
			return nil, err
		}
		dir.files[name] = data
	}
	for p, target := range snap.Links {
		dir, name, err := parent(p)
		if err != nil {
			return nil, err
		}
		dir.symlinks[name] = target
	}
	cores := kernel.KernelFromContext(ctx).ApplicationCores()
	var collapseNUMA func(*dirTree)
	collapseNUMA = func(t *dirTree) {
		t.collapseNUMA(cores)
		for _, child := range t.children {
			collapseNUMA(child)
		}
	}
	collapseNUMA(root.get("devices"))
	return &sysfsDirs{
		devices:       root.get("devices"),
		class:         fs.dirTreeEntries(ctx, creds, root.get("class")),
		busPCIDevices: fs.dirTreeEntries(ctx, creds, root.get("bus/pci/devices")),
		busPCIDrivers: fs.dirTreeEntries(ctx, creds, root.get("bus/pci/drivers")),
		devChar:       fs.dirTreeEntries(ctx, creds, root.get("dev/char")),
	}, nil
}
