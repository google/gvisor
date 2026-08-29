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

// Package config defines all syscalls the gofer is allowed to make to the
// host.
package config

import (
	"fmt"
	"os"
	"runtime"
	"strings"

	"gvisor.dev/gvisor/pkg/seccomp"
	"gvisor.dev/gvisor/pkg/seccomp/precompiledseccomp"
)

// selfPIDVarName is the variable name for the current process ID used in
// the precompiled seccomp filters.
const selfPIDVarName = "self_pid"

// Options are seccomp filter related options.
type Options struct {
	UDSOpenEnabled   bool
	UDSCreateEnabled bool
	ProfileEnabled   bool
	DirectFS         bool
	LisafsNeeded     bool
	CgoEnabled       bool
	ExtraRules       []seccomp.SyscallRules
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
// at runtime (e.g. the gofer's own PID).
func (opt Options) ConfigKey() string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "GOARCH=%q ", runtime.GOARCH)
	fmt.Fprintf(&sb, "UDSOpenEnabled=%t ", opt.UDSOpenEnabled)
	fmt.Fprintf(&sb, "UDSCreateEnabled=%t ", opt.UDSCreateEnabled)
	fmt.Fprintf(&sb, "ProfileEnabled=%t ", opt.ProfileEnabled)
	fmt.Fprintf(&sb, "DirectFS=%t ", opt.DirectFS)
	fmt.Fprintf(&sb, "LisafsNeeded=%t ", opt.LisafsNeeded)
	fmt.Fprintf(&sb, "Instrumentation=%t ", isInstrumentationEnabled())
	fmt.Fprintf(&sb, "CgoEnabled=%t ", opt.CgoEnabled)
	// Extra rules come from registered extensions, whose filters are not
	// known at precompile time. Cannot precompile.
	fmt.Fprintf(&sb, "ExtraRules=%t ", len(opt.ExtraRules) > 0)
	return strings.TrimSpace(sb.String())
}

// Warnings returns a set of warnings that may be useful to display to the
// user when the given options are used.
func Warnings(opt Options) []string {
	var warnings []string
	if opt.ProfileEnabled {
		warnings = append(warnings, "profile enabled: syscall filters less restrictive!")
	}
	if opt.UDSOpenEnabled || opt.UDSCreateEnabled {
		warnings = append(warnings, "host UDS enabled: syscall filters less restrictive!")
	}
	if opt.CgoEnabled {
		warnings = append(warnings, "CGO enabled: syscall filters less restrictive!")
	}
	return warnings
}

// Vars returns the values to use for rendering the precompiled seccomp
// program.
func (opt Options) Vars() precompiledseccomp.Values {
	vars := precompiledseccomp.Values{}
	vars.SetUint64(selfPIDVarName, uint64(os.Getpid()))
	return vars
}

// Rules returns the seccomp rules and denyRules to use for the gofer.
func Rules(opt Options) (seccomp.SyscallRules, seccomp.SyscallRules) {
	return rules(opt, opt.Vars())
}

// rules returns the seccomp rules and denyRules to use for the gofer,
// using `vars` as override for variables defined during precompilation.
func rules(opt Options, vars precompiledseccomp.Values) (seccomp.SyscallRules, seccomp.SyscallRules) {
	s := allowedSyscalls.Copy()
	s.Merge(selfPIDFilters(vars.GetUint64(selfPIDVarName)))
	if opt.ProfileEnabled {
		s.Merge(profileFilters)
	}
	if opt.UDSOpenEnabled || opt.UDSCreateEnabled {
		s.Merge(udsCommonSyscalls)
		if opt.UDSOpenEnabled {
			s.Merge(udsOpenSyscalls)
		}
		if opt.UDSCreateEnabled {
			s.Merge(udsCreateSyscalls)
		}
	}
	if opt.CgoEnabled {
		s.Merge(cgoFilters)
	}
	s.Merge(instrumentationFilters())
	// When DirectFS is not enabled, filters for LisaFS are installed.
	// Also needed when needing to serve a mount that disallows DirectFS.
	if !opt.DirectFS || opt.LisafsNeeded {
		s.Merge(lisafsFilters)
	}
	for _, rules := range opt.ExtraRules {
		s.Merge(rules)
	}
	return s, seccomp.DenyNewExecMappings
}
