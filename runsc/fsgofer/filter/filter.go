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

// Package filter defines all syscalls the gofer is allowed to make, and
// installs seccomp filters to prevent prohibited syscalls in case it's
// compromised.
package filter

import (
	"gvisor.dev/gvisor/pkg/seccomp"
)

// Install installs seccomp filters.
func Install() error {
	// Set of additional filters used by -race and -msan. Returns empty
	// when not enabled.
	allowedSyscalls.Merge(instrumentationFilters())

	return seccomp.Install(allowedSyscalls)
}

// InstallUDSFilters extends the allowed syscalls to include those necessary for
// connecting to a host UDS.
func InstallUDSFilters() {
	// Add additional filters required for connecting to the host's sockets.
	allowedSyscalls.Merge(udsSyscalls)
}

// InstallXattrFilters extends the allowed syscalls to include xattr calls that
// are necessary for Verity enabled file systems.
func InstallXattrFilters() {
	allowedSyscalls.Merge(xattrSyscalls)
}
