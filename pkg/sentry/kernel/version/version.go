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

	// LinuxRelease is the Linux release version number advertised by gVisor.
	//
	// Must be high enough to satisfy the NT_GNU_ABI_TAG minimum-kernel check
	// performed by glibc's dynamic linker; otherwise dlopen() rejects modern
	// shared libraries (e.g. libQt6Core.so.6 requires >= 4.11.0) with a
	// misleading ENOENT. Must be also high enough to not push systemd into
	// `Tainted: unmerged-bin:old-kernel`.  The "-gvisor" suffix follows the
	// distro-kernel convention.
	LinuxRelease = "5.15.0-gvisor"

	// LinuxVersion is the version info advertised by gVisor.
	LinuxVersion = "#1 SMP Sun Jan 10 15:06:54 PST 2016"
)
