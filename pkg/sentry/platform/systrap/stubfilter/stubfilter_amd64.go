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

//go:build amd64
// +build amd64

package stubfilter

import (
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/seccomp"
	"gvisor.dev/gvisor/pkg/seccomp/precompiledseccomp"
)

// setAMXVar sets the XSAVE state component for which stub threads may request
// permission. Without AMX, the rules allow only a request for a state
// component that doesn't exist, which the host rejects.
func setAMXVar(vars precompiledseccomp.Values, amx bool) {
	// Larger than any XSAVE state component index.
	const noXfeature = 64
	xfeature := uint64(noXfeature)
	if amx {
		xfeature = linux.XFEATURE_XTILEDATA
	}
	vars.SetUint64(amxXfeatureVar, xfeature)
}

func setStubProcessArchVars(vars precompiledseccomp.Values, amx bool) {
	setAMXVar(vars, amx)
}

func setSysmsgThreadArchVars(vars precompiledseccomp.Values, stubStart uint64, amx bool) {
	vars.SetUint64(stubStartVar, stubStart)
	setAMXVar(vars, amx)
}

func stubProcessArchRules(vars precompiledseccomp.Values) []seccomp.RuleSet {
	return []seccomp.RuleSet{
		// Rules for trapping vsyscall access.
		{
			Rules: seccomp.MakeSyscallRules(map[uintptr]seccomp.SyscallRule{
				unix.SYS_GETTIMEOFDAY: seccomp.MatchAll{},
				unix.SYS_TIME:         seccomp.MatchAll{},
				unix.SYS_GETCPU:       seccomp.MatchAll{}, // SYS_GETCPU was not defined in package syscall on amd64.
			}),
			Action:   seccomp.Trap,
			Vsyscall: true,
		},
		{
			Rules: seccomp.MakeSyscallRules(map[uintptr]seccomp.SyscallRule{
				unix.SYS_ARCH_PRCTL: seccomp.Or{
					seccomp.PerArg{seccomp.EqualTo(linux.ARCH_SET_CPUID), seccomp.EqualTo(0)},
					seccomp.PerArg{seccomp.EqualTo(linux.ARCH_SET_FS)},
					seccomp.PerArg{seccomp.EqualTo(linux.ARCH_GET_FS)},
					seccomp.PerArg{seccomp.EqualTo(linux.ARCH_SET_GS)},
					seccomp.PerArg{seccomp.EqualTo(linux.ARCH_GET_GS)},
					seccomp.PerArg{seccomp.EqualTo(linux.ARCH_REQ_XCOMP_PERM), seccomp.EqualTo(vars.GetUint64(amxXfeatureVar))},
				},
			}),
			Action: seccomp.Allow,
		},
	}
}

func sysmsgThreadArchRules(vars precompiledseccomp.Values) []seccomp.RuleSet {
	stubStart := vars.GetUint64(stubStartVar)
	return []seccomp.RuleSet{
		{
			// Rules for trapping vsyscall access.
			Rules: seccomp.MakeSyscallRules(map[uintptr]seccomp.SyscallRule{
				unix.SYS_GETTIMEOFDAY: seccomp.MatchAll{},
				unix.SYS_TIME:         seccomp.MatchAll{},
				unix.SYS_GETCPU:       seccomp.MatchAll{}, // SYS_GETCPU was not defined in package syscall on amd64.
			}),
			Action:   seccomp.Trap,
			Vsyscall: true,
		},
		{
			Rules: seccomp.MakeSyscallRules(map[uintptr]seccomp.SyscallRule{
				unix.SYS_ARCH_PRCTL: seccomp.Or{
					seccomp.PerArg{
						seccomp.EqualTo(linux.ARCH_SET_FS),
						seccomp.AnyValue{},
						seccomp.AnyValue{},
						seccomp.AnyValue{},
						seccomp.AnyValue{},
						seccomp.AnyValue{},
						seccomp.GreaterThan(stubStart), // rip
					},
					seccomp.PerArg{
						seccomp.EqualTo(linux.ARCH_GET_FS),
						seccomp.AnyValue{},
						seccomp.AnyValue{},
						seccomp.AnyValue{},
						seccomp.AnyValue{},
						seccomp.AnyValue{},
						seccomp.GreaterThan(stubStart), // rip
					},
					seccomp.PerArg{
						seccomp.EqualTo(linux.ARCH_SET_GS),
						seccomp.AnyValue{},
						seccomp.AnyValue{},
						seccomp.AnyValue{},
						seccomp.AnyValue{},
						seccomp.AnyValue{},
						seccomp.GreaterThan(stubStart), // rip
					},
					seccomp.PerArg{
						seccomp.EqualTo(linux.ARCH_GET_GS),
						seccomp.AnyValue{},
						seccomp.AnyValue{},
						seccomp.AnyValue{},
						seccomp.AnyValue{},
						seccomp.AnyValue{},
						seccomp.GreaterThan(stubStart), // rip
					},
					seccomp.PerArg{
						seccomp.EqualTo(linux.ARCH_REQ_XCOMP_PERM),
						seccomp.EqualTo(vars.GetUint64(amxXfeatureVar)),
						seccomp.AnyValue{},
						seccomp.AnyValue{},
						seccomp.AnyValue{},
						seccomp.AnyValue{},
						// Only the sysmsg code requests AMX permission.
						seccomp.GreaterThan(vars.GetUint64(stubSysmsgStartVar)), // rip
					},
				},
			}),
			Action: seccomp.Allow,
		},
	}
}
