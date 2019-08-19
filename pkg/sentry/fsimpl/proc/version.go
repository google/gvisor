// Copyright 2019 The gVisor Authors.
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
	"bytes"
	"fmt"

	"gvisor.dev/gvisor/pkg/sentry/context"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

// versionData implements vfs.DynamicBytesSource for /proc/version.
//
// +stateify savable
type versionData struct {
	// k is the owning Kernel.
	k *kernel.Kernel
}

var _ vfs.DynamicBytesSource = (*versionData)(nil)

// Generate implements vfs.DynamicBytesSource.Generate.
func (v *versionData) Generate(ctx context.Context, buf *bytes.Buffer) error {
	init := v.k.GlobalInit()
	if init == nil {
		// Attempted to read before the init Task is created. This can
		// only occur during startup, which should never need to read
		// this file.
		panic("Attempted to read version before initial Task is available")
	}

	// /proc/version takes the form:
	//
	// "SYSNAME version RELEASE (COMPILE_USER@COMPILE_HOST)
	// (COMPILER_VERSION) VERSION"
	//
	// where:
	// - SYSNAME, RELEASE, and VERSION are the same as returned by
	// sys_utsname
	// - COMPILE_USER is the user that build the kernel
	// - COMPILE_HOST is the hostname of the machine on which the kernel
	// was built
	// - COMPILER_VERSION is the version reported by the building compiler
	//
	// Since we don't really want to expose build information to
	// applications, those fields are omitted.
	//
	// FIXME(mpratt): Using Version from the init task SyscallTable
	// disregards the different version a task may have (e.g., in a uts
	// namespace).
	ver := init.Leader().SyscallTable().Version
	fmt.Fprintf(buf, "%s version %s %s\n", ver.Sysname, ver.Release, ver.Version)
	return nil
}
