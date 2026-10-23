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
	"slices"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/seccomp"
)

func archRules(defaultAction seccomp.Action) []seccomp.RuleSet {
	// Rules for trapping vsyscall access.
	rules := []seccomp.RuleSet{{
		Rules: seccomp.MakeSyscallRules(map[uintptr]seccomp.SyscallRule{
			unix.SYS_GETTIMEOFDAY: seccomp.MatchAll{},
			unix.SYS_TIME:         seccomp.MatchAll{},
			unix.SYS_GETCPU:       seccomp.MatchAll{}, // SYS_GETCPU was not defined in package syscall on amd64.
		}),
		Action:   seccomp.Trap,
		Vsyscall: true,
	}}
	if defaultAction == seccomp.Allow {
		return rules
	}
	return slices.Concat(rules, []seccomp.RuleSet{{
		Rules: seccomp.MakeSyscallRules(map[uintptr]seccomp.SyscallRule{
			unix.SYS_ARCH_PRCTL: seccomp.PerArg{
				seccomp.EqualTo(linux.ARCH_SET_CPUID),
				seccomp.EqualTo(0),
			},
		}),
		Action: seccomp.Allow,
	}})
}
