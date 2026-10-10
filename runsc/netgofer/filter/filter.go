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

// Package filter defines all syscalls the netgofer is allowed to make, and
// installs seccomp filters to prevent prohibited syscalls in case it's
// compromised.
package filter

import (
	"os"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/seccomp"
	"gvisor.dev/gvisor/runsc/goferfilter"
)

// selfPIDFilters returns syscall rules that depend on the current process PID.
func selfPIDFilters() seccomp.SyscallRules {
	return seccomp.MakeSyscallRules(map[uintptr]seccomp.SyscallRule{
		unix.SYS_TGKILL: seccomp.PerArg{
			seccomp.EqualTo(uint64(os.Getpid())),
		},
	})
}

// Options are seccomp filter related options.
type Options struct {
	ProfileEnabled bool
	CgoEnabled     bool
	ExtraRules     []seccomp.SyscallRules
}

// Rules returns the seccomp rules for a netgofer process without installing them.
func Rules(opt Options) seccomp.SyscallRules {
	s := allowedSyscalls.Copy()
	s.Merge(selfPIDFilters())

	if opt.ProfileEnabled {
		report("profile enabled: syscall filters less restrictive!")
		s.Merge(goferfilter.ProfileFilters)
	}

	if opt.CgoEnabled {
		report("CGO enabled: syscall filters less restrictive!")
		s.Merge(goferfilter.CgoFilters)
	}

	// Set of additional filters used by -race and -msan. Returns empty
	// when not enabled.
	s.Merge(goferfilter.InstrumentationFilters())

	for _, rules := range opt.ExtraRules {
		s.Merge(rules)
	}
	return s
}

// ***   DEBUG TIP   ***
// If you suspect the netgofer is getting killed due to a seccomp violation,
// change this to `true` and set GOTRACEBACK=system to get a stack trace and
// register dump on violation.
const debugFilter = false

// Install installs seccomp filters.
func Install(opt Options) error {
	s := Rules(opt)
	var seccompOpts seccomp.ProgramOptions
	if debugFilter {
		log.Infof("Seccomp filter debugging is enabled; unallowed syscalls will trigger SIGSYS trap.")
		seccompOpts.DefaultAction = seccomp.Trap
	}
	program := seccomp.Program{
		RuleSets: []seccomp.RuleSet{
			{
				Rules: seccomp.DenyNewExecMappings,
			},
			{
				Rules:  s,
				Action: seccomp.Allow,
			},
		},
		Options: seccompOpts,
	}
	return program.Install(nil /* timer */)
}

// report writes a warning message to the log.
func report(msg string) {
	log.Warningf("*** SECCOMP WARNING: %s", msg)
}
