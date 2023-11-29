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
	"fmt"
	"os"
	"runtime"
	"strings"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/seccomp"
	"gvisor.dev/gvisor/pkg/seccomp/precompiledseccomp"
	"gvisor.dev/gvisor/pkg/sentry/devices/accel"
	"gvisor.dev/gvisor/pkg/sentry/devices/nvproxy"
	"gvisor.dev/gvisor/pkg/sentry/devices/tpuproxy"
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
	ControllerFD          uint32
}

// isInstrumentationEnabled returns whether there are any
// instrumentation-specific filters enabled.
func isInstrumentationEnabled() bool {
	return instrumentationFilters().Size() > 0
}

// ConfigKey returns a unique string representing this set of options.
// This is used for matching a set of `Options` at seccomp precompile
// time with the same set of `Options` at runtime.
// As such, it should encompass all fields that change the structure of
// the seccomp rules, but should not encompass fields that are only known
// at runtime (e.g. `ControllerFD`).
func (opt Options) ConfigKey() string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("GOARCH=%q ", runtime.GOARCH))
	sb.WriteString(fmt.Sprintf("Platform=%q ", opt.Platform.ConfigKey()))
	sb.WriteString(fmt.Sprintf("HostNetwork=%t ", opt.HostNetwork))
	sb.WriteString(fmt.Sprintf("HostNetworkRawSockets=%t ", opt.HostNetworkRawSockets))
	sb.WriteString(fmt.Sprintf("HostFilesystem=%t ", opt.HostFilesystem))
	sb.WriteString(fmt.Sprintf("ProfileEnable=%t ", opt.ProfileEnable))
	sb.WriteString(fmt.Sprintf("Instrumentation=%t ", isInstrumentationEnabled()))
	sb.WriteString(fmt.Sprintf("NVProxy=%t ", opt.NVProxy))
	sb.WriteString(fmt.Sprintf("TPUProxy=%t ", opt.TPUProxy))
	return strings.TrimSpace(sb.String())
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
	if isInstrumentationEnabled() {
		warnings = append(warnings, "instrumentation enabled: syscall filters less restrictive!")
	}
	if opt.NVProxy {
		warnings = append(warnings, "Nvidia GPU driver proxy enabled: syscall filters less restrictive!")
	}
	if opt.TPUProxy {
		warnings = append(warnings, "TPU device proxy enabled: syscall filters less restrictive!")
	}
	return warnings
}

// Vars returns the values to use for rendering the precompiled seccomp
// program.
func (opt Options) Vars() precompiledseccomp.Values {
	vars := precompiledseccomp.Values{
		controllerFDVarName: opt.ControllerFD,
	}
	vars.SetUint64(selfPIDVarName, uint64(os.Getpid()))
	for varName, value := range opt.Platform.Variables() {
		vars[varName] = value
	}
	return vars
}

// Rules returns the seccomp rules and denyRules to use for the Sentry.
func Rules(opt Options) (seccomp.SyscallRules, seccomp.SyscallRules) {
	return rules(opt, opt.Vars())
}

// rules returns the seccomp rules and denyRules to use for the Sentry,
// using `vars` as override for variables defined during precompilation.
func rules(opt Options, vars precompiledseccomp.Values) (seccomp.SyscallRules, seccomp.SyscallRules) {
	s := allowedSyscalls.Copy()
	s.Merge(selfPIDFilters(vars.GetUint64(selfPIDVarName)))
	s.Merge(controlServerFilters(vars[controllerFDVarName]))

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
		s.Merge(tpuproxy.Filters())
	}

	s.Merge(opt.Platform.SyscallFilters(vars))
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
