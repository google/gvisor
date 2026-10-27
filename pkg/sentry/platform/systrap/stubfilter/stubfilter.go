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

// Package stubfilter defines the seccomp-bpf programs that the systrap
// platform installs in its stub processes and threads.
package stubfilter

import (
	"fmt"
	"maps"
	"slices"

	"golang.org/x/sys/unix"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/seccomp"
	"gvisor.dev/gvisor/pkg/seccomp/precompiledseccomp"
)

// Program names.
const (
	// StubProcessName is the program installed in stub processes.
	StubProcessName = "systrap_stub_process"

	// SysmsgThreadName is the program installed in sysmsg threads.
	SysmsgThreadName = "systrap_sysmsg_thread"

	// SyscallThreadName is the program installed in syscall threads.
	SyscallThreadName = "systrap_syscall_thread"
)

// 64-bit variable names.
const (
	stubStartVar       = "stub_start"
	stubROMapLenVar    = "stub_ro_map_len"
	stubSysmsgStartVar = "stub_sysmsg_start"
)

// StubProcessVars returns the variables of the StubProcessName program.
func StubProcessVars(stubStart, stubROMapLen uint64) precompiledseccomp.Values {
	vars := precompiledseccomp.Values{}
	vars.SetUint64(stubStartVar, stubStart)
	vars.SetUint64(stubROMapLenVar, stubROMapLen)
	return vars
}

// SysmsgThreadVars returns the variables of the SysmsgThreadName program.
func SysmsgThreadVars(stubStart, stubSysmsgStart uint64) precompiledseccomp.Values {
	vars := precompiledseccomp.Values{}
	vars.SetUint64(stubSysmsgStartVar, stubSysmsgStart)
	setSysmsgThreadArchVars(vars, stubStart)
	return vars
}

// StubProcess returns the program that allows only the system calls needed by
// the stub and all its children.
func StubProcess(vars precompiledseccomp.Values) *seccomp.Program {
	stubStart := vars.GetUint64(stubStartVar)
	rules := []seccomp.RuleSet{{
		Rules: seccomp.MakeSyscallRules(map[uintptr]seccomp.SyscallRule{
			unix.SYS_CLONE: seccomp.Or{
				// Allow creation of new subprocesses (used by the master).
				seccomp.PerArg{seccomp.EqualTo(unix.CLONE_FILES | unix.CLONE_PARENT | unix.SIGCHLD)},
				seccomp.PerArg{seccomp.EqualTo(unix.CLONE_FILES | unix.SIGCHLD)},
				// Allow creation of new sysmsg thread.
				seccomp.PerArg{seccomp.EqualTo(
					unix.CLONE_FILES |
						unix.CLONE_FS |
						unix.CLONE_VM |
						unix.CLONE_PTRACE |
						linux.SIGKILL)},
			},

			// For the initial process creation.
			unix.SYS_WAIT4: seccomp.MatchAll{},
			unix.SYS_EXIT:  seccomp.MatchAll{},

			// For the stub prctl dance (all).
			unix.SYS_PRCTL: seccomp.Or{
				seccomp.PerArg{seccomp.EqualTo(unix.PR_SET_PDEATHSIG), seccomp.EqualTo(unix.SIGKILL)},
				seccomp.PerArg{seccomp.EqualTo(linux.PR_SET_NO_NEW_PRIVS), seccomp.EqualTo(1)},
				seccomp.PerArg{
					seccomp.EqualTo(unix.PR_SET_SYSCALL_USER_DISPATCH),
					seccomp.EqualTo(unix.PR_SYS_DISPATCH_ON),
					seccomp.EqualTo(stubStart),
					seccomp.EqualTo(vars.GetUint64(stubROMapLenVar)),
				},
			},
			unix.SYS_GETPPID: seccomp.MatchAll{},

			// For the stub to stop itself (all).
			unix.SYS_GETPID: seccomp.MatchAll{},
			unix.SYS_KILL: seccomp.PerArg{
				seccomp.AnyValue{},
				seccomp.EqualTo(unix.SIGSTOP),
			},

			// Injected to support the address space operations.
			unix.SYS_MMAP:   seccomp.MatchAll{},
			unix.SYS_MUNMAP: seccomp.MatchAll{},

			// For sysmsg threads. Look at sysmsg/sighandler.c for more details.
			unix.SYS_RT_SIGRETURN: seccomp.MatchAll{},
			unix.SYS_SCHED_YIELD:  seccomp.MatchAll{},
			unix.SYS_FUTEX: seccomp.Or{
				seccomp.PerArg{
					seccomp.AnyValue{},
					seccomp.EqualTo(linux.FUTEX_WAIT),
					seccomp.AnyValue{},
					seccomp.AnyValue{},
				},
				seccomp.PerArg{
					seccomp.AnyValue{},
					seccomp.EqualTo(linux.FUTEX_WAKE),
					seccomp.AnyValue{},
					seccomp.AnyValue{},
				},
			},
			unix.SYS_SIGALTSTACK: seccomp.MatchAll{},
			unix.SYS_TKILL: seccomp.PerArg{
				seccomp.AnyValue{},
				seccomp.EqualTo(unix.SIGSTOP),
			},
			unix.SYS_GETTID:     seccomp.MatchAll{},
			unix.SYS_EXIT_GROUP: seccomp.MatchAll{},
			seccomp.SYS_SECCOMP: seccomp.Or{
				seccomp.PerArg{
					seccomp.EqualTo(linux.SECCOMP_SET_MODE_FILTER),
					seccomp.EqualTo(0),
					seccomp.AnyValue{},
				},
				seccomp.PerArg{
					seccomp.EqualTo(linux.SECCOMP_SET_MODE_FILTER),
					seccomp.EqualTo(linux.SECCOMP_FILTER_FLAG_NEW_LISTENER),
					seccomp.AnyValue{},
				},
			},
		}),
		Action: seccomp.Allow,
	}}
	return &seccomp.Program{
		RuleSets: slices.Concat(rules, stubProcessArchRules()),
		Options: seccomp.ProgramOptions{
			DefaultAction: seccomp.Trap,
			BadArchAction: seccomp.Trap,
		},
	}
}

// SysmsgThread returns the program that only allows system calls made from
// the sysmsg code stub.
func SysmsgThread(vars precompiledseccomp.Values) *seccomp.Program {
	stubSysmsgStart := vars.GetUint64(stubSysmsgStartVar)
	rules := []seccomp.RuleSet{{
		// Allow instructions from the sysmsg code stub, which is limited by one page.
		Rules: seccomp.MakeSyscallRules(map[uintptr]seccomp.SyscallRule{
			unix.SYS_FUTEX: seccomp.Or{
				seccomp.PerArg{
					seccomp.GreaterThan(stubSysmsgStart),
					seccomp.EqualTo(linux.FUTEX_WAKE),
					seccomp.EqualTo(1),
					seccomp.EqualTo(0),
					seccomp.EqualTo(0),
					seccomp.EqualTo(0),
					seccomp.GreaterThan(stubSysmsgStart), // rip
				},
				seccomp.PerArg{
					seccomp.GreaterThan(stubSysmsgStart),
					seccomp.EqualTo(linux.FUTEX_WAIT),
					seccomp.AnyValue{},
					seccomp.EqualTo(0),
					seccomp.EqualTo(0),
					seccomp.EqualTo(0),
					seccomp.GreaterThan(stubSysmsgStart), // rip
				},
			},
			unix.SYS_RT_SIGRETURN: seccomp.PerArg{
				seccomp.AnyValue{},
				seccomp.AnyValue{},
				seccomp.AnyValue{},
				seccomp.AnyValue{},
				seccomp.AnyValue{},
				seccomp.AnyValue{},
				seccomp.GreaterThan(stubSysmsgStart), // rip
			},
			unix.SYS_SCHED_YIELD: seccomp.PerArg{
				seccomp.AnyValue{},
				seccomp.AnyValue{},
				seccomp.AnyValue{},
				seccomp.AnyValue{},
				seccomp.AnyValue{},
				seccomp.AnyValue{},
				seccomp.GreaterThan(stubSysmsgStart), // rip
			},
		}),
		Action: seccomp.Allow,
	}}
	return &seccomp.Program{
		RuleSets: slices.Concat(sysmsgThreadArchRules(vars), rules),
		Options: seccomp.ProgramOptions{
			DefaultAction: seccomp.Trap,
			BadArchAction: seccomp.Trap,
		},
	}
}

// SyscallThread returns the program that hands exit_group calls from syscall
// threads to the Sentry.
func SyscallThread(precompiledseccomp.Values) *seccomp.Program {
	return &seccomp.Program{
		RuleSets: []seccomp.RuleSet{{
			Rules: seccomp.MakeSyscallRules(map[uintptr]seccomp.SyscallRule{
				unix.SYS_EXIT_GROUP: seccomp.MatchAll{},
			}),
			Action: seccomp.UserNotify,
		}},
		Options: seccomp.ProgramOptions{
			DefaultAction: seccomp.Allow,
			BadArchAction: seccomp.Allow,
		},
	}
}

// PrecompiledPrograms returns the set of seccomp programs to precompile.
func PrecompiledPrograms() ([]precompiledseccomp.Program, error) {
	var programs []precompiledseccomp.Program
	for _, p := range []struct {
		name string
		vars precompiledseccomp.Values
		fn   func(precompiledseccomp.Values) *seccomp.Program
	}{
		{StubProcessName, StubProcessVars(0, 0), StubProcess},
		{SysmsgThreadName, SysmsgThreadVars(0, 0), SysmsgThread},
		{SyscallThreadName, nil, SyscallThread},
	} {
		program, err := precompiledseccomp.Precompile(p.name, slices.Collect(maps.Keys(p.vars)), p.fn)
		if err != nil {
			return nil, fmt.Errorf("cannot precompile seccomp program %q: %w", p.name, err)
		}
		programs = append(programs, program)
	}
	return programs, nil
}
