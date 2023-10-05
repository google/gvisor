// Copyright 2021 The gVisor Authors.
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

package systrap

import (
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/seccomp"
)

func appendSysThreadArchSeccompRules(rules []seccomp.RuleSet) []seccomp.RuleSet {
	return append(rules, []seccomp.RuleSet{
		{
			// Rules for trapping vsyscall access.
			Rules: seccomp.SyscallRules{
				unix.SYS_GETTIMEOFDAY: {},
				unix.SYS_TIME:         {},
				unix.SYS_GETCPU:       {}, // SYS_GETCPU was not defined in package syscall on amd64.
			},
			Action:   linux.SECCOMP_RET_TRAP,
			Vsyscall: true,
		},
		{
			Rules: seccomp.SyscallRules{
				unix.SYS_ARCH_PRCTL: {
					{
						seccomp.EqualTo(linux.ARCH_SET_FS),
						seccomp.AnyValue{},
						seccomp.AnyValue{},
						seccomp.AnyValue{},
						seccomp.AnyValue{},
						seccomp.AnyValue{},
						seccomp.GreaterThan(stubStart), // rip
					},
					{
						seccomp.EqualTo(linux.ARCH_GET_FS),
						seccomp.AnyValue{},
						seccomp.AnyValue{},
						seccomp.AnyValue{},
						seccomp.AnyValue{},
						seccomp.AnyValue{},
						seccomp.GreaterThan(stubStart), // rip
					},
				},
			},
			Action: linux.SECCOMP_RET_ALLOW,
		},
	}...)
}
