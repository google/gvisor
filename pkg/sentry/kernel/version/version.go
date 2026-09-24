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

// Package version holds the kernel versioning information.
package version

const (
	// LinuxSysname is the OS name advertised by gVisor.
	LinuxSysname = "Linux"

	// defaultRelease is the default Linux release version number advertised
	// by gVisor.
	//
	// Must be high enough to satisfy the NT_GNU_ABI_TAG minimum-kernel check
	// performed by glibc's dynamic linker; otherwise dlopen() rejects modern
	// shared libraries (e.g. libQt6Core.so.6 requires >= 4.11.0) with a
	// misleading ENOENT. 4.19 is the final LTS of the Linux 4.x series,
	// which keeps us on a 4.x base. The "-gvisor" suffix follows the
	// distro-kernel convention (e.g. "-generic", "-azure").
	defaultRelease = "4.19.0-gvisor"

	// rdmaRelease is the release advertised instead when RDMA support is
	// enabled. It must be >= 5.12 so RDMA userspace enables dmabuf-based
	// memory registration for GPUDirect: aws-ofi-nccl (the EFA NCCL
	// transport) gates ibv_reg_dmabuf_mr() on the uname(2) release, and the
	// RDMA dmabuf uverbs ioctls landed upstream in Linux 5.12. Without this
	// the EFA provider falls back to registering raw CUDA VAs, which the
	// sandbox cannot pin. Advertised only in RDMA sandboxes to limit the
	// bump's blast radius; a later change can make it the default.
	rdmaRelease = "5.15.0-gvisor"

	// LinuxVersion is the version info advertised by gVisor.
	LinuxVersion = "#1 SMP Sun Jan 10 15:06:54 PST 2016"
)

// release is the advertised release; see UseRDMARelease.
var release = defaultRelease

// LinuxRelease returns the Linux release version number advertised by gVisor.
func LinuxRelease() string {
	return release
}

// UseRDMARelease switches the advertised release to rdmaRelease. It must only
// be called during early boot.
func UseRDMARelease() {
	release = rdmaRelease
}
