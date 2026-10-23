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

// Package stubfilter defines the seccomp-bpf programs that the ptrace platform
// installs in its stub processes.
package stubfilter

import (
	"fmt"
	"slices"

	"golang.org/x/sys/unix"

	"gvisor.dev/gvisor/pkg/seccomp"
	"gvisor.dev/gvisor/pkg/seccomp/precompiledseccomp"
)

// DefaultActions are the default actions for which a stub program is
// precompiled.
var DefaultActions = []seccomp.Action{
	// Kernels >= 4.8, where seccomp runs after ptrace emulation.
	seccomp.KillThread,
	// Kernels < 4.8, where seccomp runs before ptrace emulation.
	seccomp.Allow,
	// Probe for the above.
	seccomp.ReturnError,
}

// ProgramName returns the name of the stub program with the given default
// action.
func ProgramName(defaultAction seccomp.Action) string {
	return "ptrace_stub_" + string(defaultAction)
}

// Program returns the program that allows only the system calls needed by the
// stub and all its children.
func Program(defaultAction seccomp.Action) *seccomp.Program {
	var rules []seccomp.RuleSet
	if defaultAction != seccomp.Allow {
		rules = []seccomp.RuleSet{{
			Rules: seccomp.MakeSyscallRules(map[uintptr]seccomp.SyscallRule{
				unix.SYS_CLONE: seccomp.Or{
					// Allow creation of new subprocesses (used by the master).
					seccomp.PerArg{seccomp.EqualTo(unix.CLONE_FILES | unix.SIGKILL)},
					// Allow creation of new threads within a single address space (used by address spaces).
					seccomp.PerArg{
						seccomp.EqualTo(
							unix.CLONE_FILES |
								unix.CLONE_FS |
								unix.CLONE_SIGHAND |
								unix.CLONE_THREAD |
								unix.CLONE_PTRACE |
								unix.CLONE_VM)},
				},

				// For the initial process creation.
				unix.SYS_WAIT4: seccomp.MatchAll{},
				unix.SYS_EXIT:  seccomp.MatchAll{},

				// For the stub prctl dance (all).
				unix.SYS_PRCTL:   seccomp.PerArg{seccomp.EqualTo(unix.PR_SET_PDEATHSIG), seccomp.EqualTo(unix.SIGKILL)},
				unix.SYS_GETPPID: seccomp.MatchAll{},

				// For the stub to stop itself (all).
				unix.SYS_GETPID: seccomp.MatchAll{},
				unix.SYS_KILL:   seccomp.PerArg{seccomp.AnyValue{}, seccomp.EqualTo(unix.SIGSTOP)},

				// Injected to support the address space operations.
				unix.SYS_MMAP:   seccomp.MatchAll{},
				unix.SYS_MUNMAP: seccomp.MatchAll{},
			}),
			Action: seccomp.Allow,
		}}
	}
	return &seccomp.Program{
		RuleSets: slices.Concat(rules, archRules(defaultAction)),
		Options: seccomp.ProgramOptions{
			DefaultAction: defaultAction,
			BadArchAction: defaultAction,
		},
	}
}

// PrecompiledPrograms returns the set of seccomp programs to precompile.
func PrecompiledPrograms() ([]precompiledseccomp.Program, error) {
	var programs []precompiledseccomp.Program
	for _, defaultAction := range DefaultActions {
		name := ProgramName(defaultAction)
		program, err := precompiledseccomp.Precompile(name, nil, func(precompiledseccomp.Values) *seccomp.Program {
			return Program(defaultAction)
		})
		if err != nil {
			return nil, fmt.Errorf("cannot precompile seccomp program %q: %w", name, err)
		}
		programs = append(programs, program)
	}
	return programs, nil
}
