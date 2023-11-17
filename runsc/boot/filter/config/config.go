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

// Package config defines all syscalls the sandbox is allowed to make
// to the host.
package config

import (
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/seccomp"
	"gvisor.dev/gvisor/pkg/sentry/devices/accel"
	"gvisor.dev/gvisor/pkg/sentry/devices/nvproxy"
	"gvisor.dev/gvisor/pkg/sentry/platform"
)

// Options are seccomp filter related options.
type Options struct {
	Platform              platform.SeccompInfo
	HostNetwork           bool
	HostNetworkRawSockets bool
	HostFilesystem        bool
	ProfileEnable         bool
	NVProxy               bool
	TPUProxy              bool
	ControllerFD          int
}

// Warnings returns a set of warnings that may be useful to display to the
// user when the given options are used.
func Warnings(opt Options) []string {
	var warnings []string
	if opt.HostNetwork {
		if opt.HostNetworkRawSockets {
			warnings = append(warnings, "host networking (with raw sockets) enabled: syscall filters less restrictive!")
		} else {
			warnings = append(warnings, "host networking enabled: syscall filters less restrictive!")
		}
	}
	if opt.ProfileEnable {
		warnings = append(warnings, "profile enabled: syscall filters less restrictive!")
	}
	if opt.HostFilesystem {
		warnings = append(warnings, "host filesystem enabled: syscall filters less restrictive!")
	}
	if opt.NVProxy {
		warnings = append(warnings, "Nvidia GPU driver proxy enabled: syscall filters less restrictive!")
	}
	if opt.TPUProxy {
		warnings = append(warnings, "TPU device proxy enabled: syscall filters less restrictive!")
	}
	return warnings
}

// Rules returns the seccomp rules and denyRules to use for the Sentry.
func Rules(opt Options) (seccomp.SyscallRules, seccomp.SyscallRules) {
	s := allowedSyscalls
	s.Merge(controlServerFilters(opt.ControllerFD))

	// Set of additional filters used by -race and -msan. Returns empty
	// when not enabled.
	s.Merge(instrumentationFilters())

	if opt.HostNetwork {
		s.Merge(hostInetFilters(opt.HostNetworkRawSockets))
	}
	if opt.ProfileEnable {
		s.Merge(profileFilters())
	}
	if opt.HostFilesystem {
		s.Merge(hostFilesystemFilters())
	}
	if opt.NVProxy {
		s.Merge(nvproxy.Filters())
	}
	if opt.TPUProxy {
		s.Merge(accel.Filters())
	}

	s.Merge(opt.Platform.SyscallFilters(opt.Platform.Variables()))
	return s, seccomp.DenyNewExecMappings
}

// SeccompOptions returns the seccomp program options to use for the filter.
func SeccompOptions(opt Options) seccomp.ProgramOptions {
	// futex(2) is unequivocally the most-frequently-used syscall by the
	// Sentry across all platforms.
	hotSyscalls := []uintptr{unix.SYS_FUTEX}
	// ... Then comes the platform-specific hot syscalls which are typically
	// part of the syscall interception hot path.
	hotSyscalls = append(hotSyscalls, opt.Platform.HottestSyscalls()...)
	// ... Then come a few syscalls that are frequent just from workloads in
	// general.
	hotSyscalls = append(hotSyscalls, archSpecificHotSyscalls()...)

	// Now deduplicate them.
	sysnoMap := make(map[uintptr]struct{}, len(hotSyscalls))
	uniqueHotSyscalls := make([]uintptr, 0, len(hotSyscalls))
	for _, sysno := range hotSyscalls {
		if _, alreadyAdded := sysnoMap[sysno]; !alreadyAdded {
			sysnoMap[sysno] = struct{}{}
			uniqueHotSyscalls = append(uniqueHotSyscalls, sysno)
		}
	}

	opts := seccomp.DefaultProgramOptions()
	opts.HotSyscalls = uniqueHotSyscalls
	return opts
}
