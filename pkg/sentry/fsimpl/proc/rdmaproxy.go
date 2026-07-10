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

package proc

import (
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/sentry/devices/rdmaproxy"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/kernfs"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
)

// addRDMAProxyFiles populates /proc/bus/pci with an empty devices file when
// RDMA device proxying is enabled.
//
// RDMA userspace (e.g. perftest, via libpci/pciutils) probes host PCIe
// capabilities at startup by scanning /proc/bus/pci or /sys/bus/pci; if
// every access method it tries fails outright, pciutils treats this as
// fatal and exits the caller. An empty, but present and readable,
// /proc/bus/pci/devices makes pciutils' "proc" access method succeed with
// zero enumerated devices, which is accepted as a normal (if uninteresting)
// outcome rather than a hard failure.
func (fs *filesystem) addRDMAProxyFiles(ctx context.Context, root *auth.Credentials, k *kernel.Kernel, contents map[string]kernfs.Inode) {
	if !rdmaproxy.Enabled() {
		return
	}
	contents["bus"] = fs.newStaticDir(ctx, root, map[string]kernfs.Inode{
		"pci": fs.newStaticDir(ctx, root, map[string]kernfs.Inode{
			"devices": fs.newInode(ctx, root, 0444, newStaticFile("")),
		}),
	})
}
