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

package seccomp

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"
	"io/ioutil"
	"math"
	"math/rand"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/bpf"
)

//go:embed victim
var victimData []byte

// newVictim makes a victim binary.
func newVictim() (string, error) {
	f, err := ioutil.TempFile("", "victim")
	if err != nil {
		return "", err
	}
	defer f.Close()
	path := f.Name()
	if _, err := io.Copy(f, bytes.NewBuffer(victimData)); err != nil {
		os.Remove(path)
		return "", err
	}
	if err := os.Chmod(path, 0755); err != nil {
		os.Remove(path)
		return "", err
	}
	return path, nil
}

func TestBasic(t *testing.T) {
	buf := make([]byte, (&linux.SeccompData{}).SizeBytes())

	type spec struct {
		// desc is the test's description.
		desc string

		// data is the input data.
		data linux.SeccompData

		// want is the expected return value of the BPF program.
		want linux.BPFAction
	}

	for _, test := range []struct {
		name      string
		ruleSets  []RuleSet
		wantPanic bool
		options   ProgramOptions
		specs     []spec
	}{
		{
			name: "Single syscall",
			ruleSets: []RuleSet{
				{
					Rules:  MakeSyscallRules(map[uintptr]SyscallRule{1: MatchAll{}}),
					Action: linux.SECCOMP_RET_ALLOW,
				},
			},
			options: ProgramOptions{
				DefaultAction: linux.SECCOMP_RET_TRAP,
				BadArchAction: linux.SECCOMP_RET_KILL_THREAD,
			},
			specs: []spec{
				{
					desc: "syscall allowed",
					data: linux.SeccompData{Nr: 1, Arch: LINUX_AUDIT_ARCH},
					want: linux.SECCOMP_RET_ALLOW,
				},
				{
					desc: "syscall disallowed",
					data: linux.SeccompData{Nr: 2, Arch: LINUX_AUDIT_ARCH},
					want: linux.SECCOMP_RET_TRAP,
				},
			},
		},
		{
			name: "Multiple rulesets",
			ruleSets: []RuleSet{
				{
					Rules: MakeSyscallRules(map[uintptr]SyscallRule{
						1: PerArg{
							EqualTo(0x1),
						},
					}),
					Action: linux.SECCOMP_RET_ALLOW,
				},
				{
					Rules: MakeSyscallRules(map[uintptr]SyscallRule{
						1: MatchAll{},
						2: MatchAll{},
					}),
					Action: linux.SECCOMP_RET_TRAP,
				},
			},
			options: ProgramOptions{
				DefaultAction: linux.SECCOMP_RET_KILL_THREAD,
				BadArchAction: linux.SECCOMP_RET_KILL_THREAD,
			},
			specs: []spec{
				{
					desc: "allowed (1a)",
					data: linux.SeccompData{Nr: 1, Arch: LINUX_AUDIT_ARCH, Args: [6]uint64{0x1}},
					want: linux.SECCOMP_RET_ALLOW,
				},
				{
					desc: "allowed (1b)",
					data: linux.SeccompData{Nr: 1, Arch: LINUX_AUDIT_ARCH},
					want: linux.SECCOMP_RET_TRAP,
				},
				{
					desc: "syscall 1 matched 2nd rule",
					data: linux.SeccompData{Nr: 1, Arch: LINUX_AUDIT_ARCH},
					want: linux.SECCOMP_RET_TRAP,
				},
				{
					desc: "no match",
					data: linux.SeccompData{Nr: 0, Arch: LINUX_AUDIT_ARCH},
					want: linux.SECCOMP_RET_KILL_THREAD,
				},
			},
		},
		{
			name: "Multiple syscalls",
			ruleSets: []RuleSet{
				{
					Rules: MakeSyscallRules(map[uintptr]SyscallRule{
						1: MatchAll{},
						3: MatchAll{},
						5: MatchAll{},
					}),
					Action: linux.SECCOMP_RET_ALLOW,
				},
			},
			options: ProgramOptions{
				DefaultAction: linux.SECCOMP_RET_TRAP,
				BadArchAction: linux.SECCOMP_RET_KILL_THREAD,
			},
			specs: []spec{
				{
					desc: "allowed (1)",
					data: linux.SeccompData{Nr: 1, Arch: LINUX_AUDIT_ARCH},
					want: linux.SECCOMP_RET_ALLOW,
				},
				{
					desc: "allowed (3)",
					data: linux.SeccompData{Nr: 3, Arch: LINUX_AUDIT_ARCH},
					want: linux.SECCOMP_RET_ALLOW,
				},
				{
					desc: "allowed (5)",
					data: linux.SeccompData{Nr: 5, Arch: LINUX_AUDIT_ARCH},
					want: linux.SECCOMP_RET_ALLOW,
				},
				{
					desc: "disallowed (0)",
					data: linux.SeccompData{Nr: 0, Arch: LINUX_AUDIT_ARCH},
					want: linux.SECCOMP_RET_TRAP,
				},
				{
					desc: "disallowed (2)",
					data: linux.SeccompData{Nr: 2, Arch: LINUX_AUDIT_ARCH},
					want: linux.SECCOMP_RET_TRAP,
				},
				{
					desc: "disallowed (4)",
					data: linux.SeccompData{Nr: 4, Arch: LINUX_AUDIT_ARCH},
					want: linux.SECCOMP_RET_TRAP,
				},
				{
					desc: "disallowed (6)",
					data: linux.SeccompData{Nr: 6, Arch: LINUX_AUDIT_ARCH},
					want: linux.SECCOMP_RET_TRAP,
				},
				{
					desc: "disallowed (100)",
					data: linux.SeccompData{Nr: 100, Arch: LINUX_AUDIT_ARCH},
					want: linux.SECCOMP_RET_TRAP,
				},
			},
		},
		{
			name: "Wrong architecture",
			ruleSets: []RuleSet{
				{
					Rules: MakeSyscallRules(map[uintptr]SyscallRule{
						1: MatchAll{},
					}),
					Action: linux.SECCOMP_RET_ALLOW,
				},
			},
			options: ProgramOptions{
				DefaultAction: linux.SECCOMP_RET_TRAP,
				BadArchAction: linux.SECCOMP_RET_KILL_THREAD,
			},
			specs: []spec{
				{
					desc: "arch (123)",
					data: linux.SeccompData{Nr: 1, Arch: 123},
					want: linux.SECCOMP_RET_KILL_THREAD,
				},
			},
		},
		{
			name: "Syscall disallowed",
			ruleSets: []RuleSet{
				{
					Rules: MakeSyscallRules(map[uintptr]SyscallRule{
						1: MatchAll{},
					}),
					Action: linux.SECCOMP_RET_ALLOW,
				},
			},
			options: ProgramOptions{
				DefaultAction: linux.SECCOMP_RET_TRAP,
				BadArchAction: linux.SECCOMP_RET_KILL_THREAD,
			},
			specs: []spec{
				{
					desc: "action trap",
					data: linux.SeccompData{Nr: 2, Arch: LINUX_AUDIT_ARCH},
					want: linux.SECCOMP_RET_TRAP,
				},
			},
		},
		{
			name: "Syscall arguments",
			ruleSets: []RuleSet{
				{
					Rules: MakeSyscallRules(map[uintptr]SyscallRule{
						1: PerArg{
							AnyValue{},
							EqualTo(0xf),
						},
					}),
					Action: linux.SECCOMP_RET_ALLOW,
				},
			},
			options: ProgramOptions{
				DefaultAction: linux.SECCOMP_RET_TRAP,
				BadArchAction: linux.SECCOMP_RET_KILL_THREAD,
			},
			specs: []spec{
				{
					desc: "allowed",
					data: linux.SeccompData{Nr: 1, Arch: LINUX_AUDIT_ARCH, Args: [6]uint64{0xf, 0xf}},
					want: linux.SECCOMP_RET_ALLOW,
				},
				{
					desc: "disallowed",
					data: linux.SeccompData{Nr: 1, Arch: LINUX_AUDIT_ARCH, Args: [6]uint64{0xf, 0xe}},
					want: linux.SECCOMP_RET_TRAP,
				},
			},
		},
		{
			name: "Multiple arguments",
			ruleSets: []RuleSet{
				{
					Rules: MakeSyscallRules(map[uintptr]SyscallRule{
						1: Or{
							PerArg{
								EqualTo(0xf),
							},
							PerArg{
								EqualTo(0xe),
							},
						},
					}),
					Action: linux.SECCOMP_RET_ALLOW,
				},
			},
			options: ProgramOptions{
				DefaultAction: linux.SECCOMP_RET_TRAP,
				BadArchAction: linux.SECCOMP_RET_KILL_THREAD,
			},
			specs: []spec{
				{
					desc: "match first rule",
					data: linux.SeccompData{Nr: 1, Arch: LINUX_AUDIT_ARCH, Args: [6]uint64{0xf}},
					want: linux.SECCOMP_RET_ALLOW,
				},
				{
					desc: "match 2nd rule",
					data: linux.SeccompData{Nr: 1, Arch: LINUX_AUDIT_ARCH, Args: [6]uint64{0xe}},
					want: linux.SECCOMP_RET_ALLOW,
				},
				{
					desc: "match neither rule",
					data: linux.SeccompData{Nr: 1, Arch: LINUX_AUDIT_ARCH, Args: [6]uint64{0xd}},
					want: linux.SECCOMP_RET_TRAP,
				},
			},
		},
		{
			name: "empty Or is invalid",
			ruleSets: []RuleSet{
				{
					Rules: MakeSyscallRules(map[uintptr]SyscallRule{
						1: Or{},
					}),
					Action: linux.SECCOMP_RET_ALLOW,
				},
			},
			wantPanic: true,
		},
		{
			name: "And of multiple rules",
			ruleSets: []RuleSet{
				{
					Rules: MakeSyscallRules(map[uintptr]SyscallRule{
						1: And{
							PerArg{
								NotEqual(0xf),
							},
							PerArg{
								NotEqual(0xe),
							},
						},
					}),
					Action: linux.SECCOMP_RET_ALLOW,
				},
			},
			options: ProgramOptions{
				DefaultAction: linux.SECCOMP_RET_TRAP,
				BadArchAction: linux.SECCOMP_RET_KILL_THREAD,
			},
			specs: []spec{
				{
					desc: "hit first rule",
					data: linux.SeccompData{Nr: 1, Arch: LINUX_AUDIT_ARCH, Args: [6]uint64{0xf}},
					want: linux.SECCOMP_RET_TRAP,
				},
				{
					desc: "hit 2nd rule",
					data: linux.SeccompData{Nr: 1, Arch: LINUX_AUDIT_ARCH, Args: [6]uint64{0xe}},
					want: linux.SECCOMP_RET_TRAP,
				},
				{
					desc: "hit neither rule",
					data: linux.SeccompData{Nr: 1, Arch: LINUX_AUDIT_ARCH, Args: [6]uint64{0xd}},
					want: linux.SECCOMP_RET_ALLOW,
				},
			},
		},
		{
			name: "empty And is invalid",
			ruleSets: []RuleSet{
				{
					Rules: MakeSyscallRules(map[uintptr]SyscallRule{
						1: And{},
					}),
					Action: linux.SECCOMP_RET_ALLOW,
				},
			},
			wantPanic: true,
		},
		{
			name: "EqualTo",
			ruleSets: []RuleSet{
				{
					Rules: MakeSyscallRules(map[uintptr]SyscallRule{
						1: PerArg{
							EqualTo(0),
							EqualTo(math.MaxUint64 - 1),
							EqualTo(math.MaxUint32),
						},
					}),
					Action: linux.SECCOMP_RET_ALLOW,
				},
			},
			options: ProgramOptions{
				DefaultAction: linux.SECCOMP_RET_TRAP,
				BadArchAction: linux.SECCOMP_RET_KILL_THREAD,
			},
			specs: []spec{
				{
					desc: "argument allowed (all match)",
					data: linux.SeccompData{
						Nr:   1,
						Arch: LINUX_AUDIT_ARCH,
						Args: [6]uint64{0, math.MaxUint64 - 1, math.MaxUint32},
					},
					want: linux.SECCOMP_RET_ALLOW,
				},
				{
					desc: "argument disallowed (one mismatch)",
					data: linux.SeccompData{
						Nr:   1,
						Arch: LINUX_AUDIT_ARCH,
						Args: [6]uint64{0, math.MaxUint64, math.MaxUint32},
					},
					want: linux.SECCOMP_RET_TRAP,
				},
				{
					desc: "argument disallowed (multiple mismatch)",
					data: linux.SeccompData{
						Nr:   1,
						Arch: LINUX_AUDIT_ARCH,
						Args: [6]uint64{0, math.MaxUint64, math.MaxUint32 - 1},
					},
					want: linux.SECCOMP_RET_TRAP,
				},
			},
		},
		{
			name: "NotEqual",
			ruleSets: []RuleSet{
				{
					Rules: MakeSyscallRules(map[uintptr]SyscallRule{
						1: PerArg{
							NotEqual(0x7aabbccdd),
							NotEqual(math.MaxUint64 - 1),
							NotEqual(math.MaxUint32),
						},
					}),
					Action: linux.SECCOMP_RET_ALLOW,
				},
			},
			options: ProgramOptions{
				DefaultAction: linux.SECCOMP_RET_TRAP,
				BadArchAction: linux.SECCOMP_RET_KILL_THREAD,
			},
			specs: []spec{
				{
					desc: "arg allowed",
					data: linux.SeccompData{
						Nr:   1,
						Arch: LINUX_AUDIT_ARCH,
						Args: [6]uint64{0, math.MaxUint64, math.MaxUint32 - 1},
					},
					want: linux.SECCOMP_RET_ALLOW,
				},
				{
					desc: "arg disallowed (one equal)",
					data: linux.SeccompData{
						Nr:   1,
						Arch: LINUX_AUDIT_ARCH,
						Args: [6]uint64{0x7aabbccdd, math.MaxUint64, math.MaxUint32 - 1},
					},
					want: linux.SECCOMP_RET_TRAP,
				},
				{
					desc: "arg disallowed (all equal)",
					data: linux.SeccompData{
						Nr:   1,
						Arch: LINUX_AUDIT_ARCH,
						Args: [6]uint64{0x7aabbccdd, math.MaxUint64 - 1, math.MaxUint32},
					},
					want: linux.SECCOMP_RET_TRAP,
				},
			},
		},
		{
			name: "GreaterThan",
			ruleSets: []RuleSet{
				{
					Rules: MakeSyscallRules(map[uintptr]SyscallRule{
						1: PerArg{
							// 4294967298
							// Both upper 32 bits and lower 32 bits are non-zero.
							// 00000000000000000000000000000010
							// 00000000000000000000000000000010
							GreaterThan(0x00000002_00000002),
						},
					}),
					Action: linux.SECCOMP_RET_ALLOW,
				},
			},
			options: ProgramOptions{
				DefaultAction: linux.SECCOMP_RET_TRAP,
				BadArchAction: linux.SECCOMP_RET_KILL_THREAD,
			},
			specs: []spec{
				{
					desc: "high 32bits greater",
					data: linux.SeccompData{Nr: 1, Arch: LINUX_AUDIT_ARCH, Args: [6]uint64{0x00000003_00000002}},
					want: linux.SECCOMP_RET_ALLOW,
				},
				{
					desc: "high 32bits equal, low 32bits greater",
					data: linux.SeccompData{Nr: 1, Arch: LINUX_AUDIT_ARCH, Args: [6]uint64{0x00000002_00000003}},
					want: linux.SECCOMP_RET_ALLOW,
				},
				{
					desc: "high 32bits equal, low 32bits equal",
					data: linux.SeccompData{Nr: 1, Arch: LINUX_AUDIT_ARCH, Args: [6]uint64{0x00000002_00000002}},
					want: linux.SECCOMP_RET_TRAP,
				},
				{
					desc: "high 32bits equal, low 32bits less",
					data: linux.SeccompData{Nr: 1, Arch: LINUX_AUDIT_ARCH, Args: [6]uint64{0x00000002_00000001}},
					want: linux.SECCOMP_RET_TRAP,
				},
				{
					desc: "high 32bits less",
					data: linux.SeccompData{Nr: 1, Arch: LINUX_AUDIT_ARCH, Args: [6]uint64{0x00000001_00000003}},
					want: linux.SECCOMP_RET_TRAP,
				},
			},
		},
		{
			name: "GreaterThan (multi)",
			ruleSets: []RuleSet{
				{
					Rules: MakeSyscallRules(map[uintptr]SyscallRule{
						1: PerArg{
							GreaterThan(0xf),
							GreaterThan(0xabcd000d),
						},
					}),
					Action: linux.SECCOMP_RET_ALLOW,
				},
			},
			options: ProgramOptions{
				DefaultAction: linux.SECCOMP_RET_TRAP,
				BadArchAction: linux.SECCOMP_RET_KILL_THREAD,
			},
			specs: []spec{
				{
					desc: "arg allowed",
					data: linux.SeccompData{Nr: 1, Arch: LINUX_AUDIT_ARCH, Args: [6]uint64{0x10, 0xffffffff}},
					want: linux.SECCOMP_RET_ALLOW,
				},
				{
					desc: "arg disallowed (first arg equal)",
					data: linux.SeccompData{Nr: 1, Arch: LINUX_AUDIT_ARCH, Args: [6]uint64{0xf, 0xffffffff}},
					want: linux.SECCOMP_RET_TRAP,
				},
				{
					desc: "arg disallowed (first arg smaller)",
					data: linux.SeccompData{Nr: 1, Arch: LINUX_AUDIT_ARCH, Args: [6]uint64{0x0, 0xffffffff}},
					want: linux.SECCOMP_RET_TRAP,
				},
				{
					desc: "arg disallowed (second arg equal)",
					data: linux.SeccompData{Nr: 1, Arch: LINUX_AUDIT_ARCH, Args: [6]uint64{0x10, 0xabcd000d}},
					want: linux.SECCOMP_RET_TRAP,
				},
				{
					desc: "arg disallowed (second arg smaller)",
					data: linux.SeccompData{Nr: 1, Arch: LINUX_AUDIT_ARCH, Args: [6]uint64{0x10, 0xa000ffff}},
					want: linux.SECCOMP_RET_TRAP,
				},
			},
		},
		{
			name: "GreaterThanOrEqual",
			ruleSets: []RuleSet{
				{
					Rules: MakeSyscallRules(map[uintptr]SyscallRule{
						1: PerArg{
							// 4294967298
							// Both upper 32 bits and lower 32 bits are non-zero.
							// 00000000000000000000000000000010
							// 00000000000000000000000000000010
							GreaterThanOrEqual(0x00000002_00000002),
						},
					}),
					Action: linux.SECCOMP_RET_ALLOW,
				},
			},
			options: ProgramOptions{
				DefaultAction: linux.SECCOMP_RET_TRAP,
				BadArchAction: linux.SECCOMP_RET_KILL_THREAD,
			},
			specs: []spec{
				{
					desc: "high 32bits greater",
					data: linux.SeccompData{Nr: 1, Arch: LINUX_AUDIT_ARCH, Args: [6]uint64{0x00000003_00000002}},
					want: linux.SECCOMP_RET_ALLOW,
				},
				{
					desc: "high 32bits equal, low 32bits greater",
					data: linux.SeccompData{Nr: 1, Arch: LINUX_AUDIT_ARCH, Args: [6]uint64{0x00000002_00000003}},
					want: linux.SECCOMP_RET_ALLOW,
				},
				{
					desc: "high 32bits equal, low 32bits equal",
					data: linux.SeccompData{Nr: 1, Arch: LINUX_AUDIT_ARCH, Args: [6]uint64{0x00000002_00000002}},
					want: linux.SECCOMP_RET_ALLOW,
				},
				{
					desc: "high 32bits equal, low 32bits less",
					data: linux.SeccompData{Nr: 1, Arch: LINUX_AUDIT_ARCH, Args: [6]uint64{0x00000002_00000001}},
					want: linux.SECCOMP_RET_TRAP,
				},
				{
					desc: "high 32bits less",
					data: linux.SeccompData{Nr: 1, Arch: LINUX_AUDIT_ARCH, Args: [6]uint64{0x00000001_00000002}},
					want: linux.SECCOMP_RET_TRAP,
				},
			},
		},
		{
			name: "GreaterThanOrEqual (multi)",
			ruleSets: []RuleSet{
				{
					Rules: MakeSyscallRules(map[uintptr]SyscallRule{
						1: PerArg{
							GreaterThanOrEqual(0xf),
							GreaterThanOrEqual(0xabcd000d),
						},
					}),
					Action: linux.SECCOMP_RET_ALLOW,
				},
			},
			options: ProgramOptions{
				DefaultAction: linux.SECCOMP_RET_TRAP,
				BadArchAction: linux.SECCOMP_RET_KILL_THREAD,
			},
			specs: []spec{
				{
					desc: "arg allowed (both greater)",
					data: linux.SeccompData{Nr: 1, Arch: LINUX_AUDIT_ARCH, Args: [6]uint64{0x10, 0xffffffff}},
					want: linux.SECCOMP_RET_ALLOW,
				},
				{
					desc: "arg allowed (first arg equal)",
					data: linux.SeccompData{Nr: 1, Arch: LINUX_AUDIT_ARCH, Args: [6]uint64{0xf, 0xffffffff}},
					want: linux.SECCOMP_RET_ALLOW,
				},
				{
					desc: "arg disallowed (first arg smaller)",
					data: linux.SeccompData{Nr: 1, Arch: LINUX_AUDIT_ARCH, Args: [6]uint64{0x0, 0xffffffff}},
					want: linux.SECCOMP_RET_TRAP,
				},
				{
					desc: "arg allowed (second arg equal)",
					data: linux.SeccompData{Nr: 1, Arch: LINUX_AUDIT_ARCH, Args: [6]uint64{0x10, 0xabcd000d}},
					want: linux.SECCOMP_RET_ALLOW,
				},
				{
					desc: "arg disallowed (second arg smaller)",
					data: linux.SeccompData{Nr: 1, Arch: LINUX_AUDIT_ARCH, Args: [6]uint64{0x10, 0xa000ffff}},
					want: linux.SECCOMP_RET_TRAP,
				},
				{
					desc: "arg disallowed (both arg smaller)",
					data: linux.SeccompData{Nr: 1, Arch: LINUX_AUDIT_ARCH, Args: [6]uint64{0x0, 0xa000ffff}},
					want: linux.SECCOMP_RET_TRAP,
				},
			},
		},
		{
			name: "LessThan",
			ruleSets: []RuleSet{
				{
					Rules: MakeSyscallRules(map[uintptr]SyscallRule{
						1: PerArg{
							// 4294967298
							// Both upper 32 bits and lower 32 bits are non-zero.
							// 00000000000000000000000000000010
							// 00000000000000000000000000000010
							LessThan(0x00000002_00000002),
						},
					}),
					Action: linux.SECCOMP_RET_ALLOW,
				},
			},
			options: ProgramOptions{
				DefaultAction: linux.SECCOMP_RET_TRAP,
				BadArchAction: linux.SECCOMP_RET_KILL_THREAD,
			},
			specs: []spec{
				{
					desc: "high 32bits greater",
					data: linux.SeccompData{Nr: 1, Arch: LINUX_AUDIT_ARCH, Args: [6]uint64{0x00000003_00000002}},
					want: linux.SECCOMP_RET_TRAP,
				},
				{
					desc: "high 32bits equal, low 32bits greater",
					data: linux.SeccompData{Nr: 1, Arch: LINUX_AUDIT_ARCH, Args: [6]uint64{0x00000002_00000003}},
					want: linux.SECCOMP_RET_TRAP,
				},
				{
					desc: "high 32bits equal, low 32bits equal",
					data: linux.SeccompData{Nr: 1, Arch: LINUX_AUDIT_ARCH, Args: [6]uint64{0x00000002_00000002}},
					want: linux.SECCOMP_RET_TRAP,
				},
				{
					desc: "high 32bits equal, low 32bits less",
					data: linux.SeccompData{Nr: 1, Arch: LINUX_AUDIT_ARCH, Args: [6]uint64{0x00000002_00000001}},
					want: linux.SECCOMP_RET_ALLOW,
				},
				{
					desc: "high 32bits less",
					data: linux.SeccompData{Nr: 1, Arch: LINUX_AUDIT_ARCH, Args: [6]uint64{0x00000001_00000002}},
					want: linux.SECCOMP_RET_ALLOW,
				},
			},
		},
		{
			name: "LessThan (multi)",
			ruleSets: []RuleSet{
				{
					Rules: MakeSyscallRules(map[uintptr]SyscallRule{
						1: PerArg{
							LessThan(0x1),
							LessThan(0xabcd000d),
						},
					}),
					Action: linux.SECCOMP_RET_ALLOW,
				},
			},
			options: ProgramOptions{
				DefaultAction: linux.SECCOMP_RET_TRAP,
				BadArchAction: linux.SECCOMP_RET_KILL_THREAD,
			},
			specs: []spec{
				{
					desc: "arg allowed",
					data: linux.SeccompData{Nr: 1, Arch: LINUX_AUDIT_ARCH, Args: [6]uint64{0x0, 0x0}},
					want: linux.SECCOMP_RET_ALLOW,
				},
				{
					desc: "arg disallowed (first arg equal)",
					data: linux.SeccompData{Nr: 1, Arch: LINUX_AUDIT_ARCH, Args: [6]uint64{0x1, 0x0}},
					want: linux.SECCOMP_RET_TRAP,
				},
				{
					desc: "arg disallowed (first arg greater)",
					data: linux.SeccompData{Nr: 1, Arch: LINUX_AUDIT_ARCH, Args: [6]uint64{0x2, 0x0}},
					want: linux.SECCOMP_RET_TRAP,
				},
				{
					desc: "arg disallowed (second arg equal)",
					data: linux.SeccompData{Nr: 1, Arch: LINUX_AUDIT_ARCH, Args: [6]uint64{0x0, 0xabcd000d}},
					want: linux.SECCOMP_RET_TRAP,
				},
				{
					desc: "arg disallowed (second arg greater)",
					data: linux.SeccompData{Nr: 1, Arch: LINUX_AUDIT_ARCH, Args: [6]uint64{0x0, 0xffffffff}},
					want: linux.SECCOMP_RET_TRAP,
				},
				{
					desc: "arg disallowed (both arg greater)",
					data: linux.SeccompData{Nr: 1, Arch: LINUX_AUDIT_ARCH, Args: [6]uint64{0x2, 0xffffffff}},
					want: linux.SECCOMP_RET_TRAP,
				},
			},
		},
		{
			name: "LessThanOrEqual",
			ruleSets: []RuleSet{
				{
					Rules: MakeSyscallRules(map[uintptr]SyscallRule{
						1: PerArg{
							// 4294967298
							// Both upper 32 bits and lower 32 bits are non-zero.
							// 00000000000000000000000000000010
							// 00000000000000000000000000000010
							LessThanOrEqual(0x00000002_00000002),
						},
					}),
					Action: linux.SECCOMP_RET_ALLOW,
				},
			},
			options: ProgramOptions{
				DefaultAction: linux.SECCOMP_RET_TRAP,
				BadArchAction: linux.SECCOMP_RET_KILL_THREAD,
			},
			specs: []spec{
				{
					desc: "high 32bits greater",
					data: linux.SeccompData{Nr: 1, Arch: LINUX_AUDIT_ARCH, Args: [6]uint64{0x00000003_00000002}},
					want: linux.SECCOMP_RET_TRAP,
				},
				{
					desc: "high 32bits equal, low 32bits greater",
					data: linux.SeccompData{Nr: 1, Arch: LINUX_AUDIT_ARCH, Args: [6]uint64{0x00000002_00000003}},
					want: linux.SECCOMP_RET_TRAP,
				},
				{
					desc: "high 32bits equal, low 32bits equal",
					data: linux.SeccompData{Nr: 1, Arch: LINUX_AUDIT_ARCH, Args: [6]uint64{0x00000002_00000002}},
					want: linux.SECCOMP_RET_ALLOW,
				},
				{
					desc: "high 32bits equal, low 32bits less",
					data: linux.SeccompData{Nr: 1, Arch: LINUX_AUDIT_ARCH, Args: [6]uint64{0x00000002_00000001}},
					want: linux.SECCOMP_RET_ALLOW,
				},
				{
					desc: "high 32bits less",
					data: linux.SeccompData{Nr: 1, Arch: LINUX_AUDIT_ARCH, Args: [6]uint64{0x00000001_00000002}},
					want: linux.SECCOMP_RET_ALLOW,
				},
			},
		},

		{
			name: "LessThanOrEqual (multi)",
			ruleSets: []RuleSet{
				{
					Rules: MakeSyscallRules(map[uintptr]SyscallRule{
						1: PerArg{
							LessThanOrEqual(0x1),
							LessThanOrEqual(0xabcd000d),
						},
					}),
					Action: linux.SECCOMP_RET_ALLOW,
				},
			},
			options: ProgramOptions{
				DefaultAction: linux.SECCOMP_RET_TRAP,
				BadArchAction: linux.SECCOMP_RET_KILL_THREAD,
			},
			specs: []spec{
				{
					desc: "arg allowed",
					data: linux.SeccompData{Nr: 1, Arch: LINUX_AUDIT_ARCH, Args: [6]uint64{0x0, 0x0}},
					want: linux.SECCOMP_RET_ALLOW,
				},
				{
					desc: "arg allowed (first arg equal)",
					data: linux.SeccompData{Nr: 1, Arch: LINUX_AUDIT_ARCH, Args: [6]uint64{0x1, 0x0}},
					want: linux.SECCOMP_RET_ALLOW,
				},
				{
					desc: "arg disallowed (first arg greater)",
					data: linux.SeccompData{Nr: 1, Arch: LINUX_AUDIT_ARCH, Args: [6]uint64{0x2, 0x0}},
					want: linux.SECCOMP_RET_TRAP,
				},
				{
					desc: "arg allowed (second arg equal)",
					data: linux.SeccompData{Nr: 1, Arch: LINUX_AUDIT_ARCH, Args: [6]uint64{0x0, 0xabcd000d}},
					want: linux.SECCOMP_RET_ALLOW,
				},
				{
					desc: "arg disallowed (second arg greater)",
					data: linux.SeccompData{Nr: 1, Arch: LINUX_AUDIT_ARCH, Args: [6]uint64{0x0, 0xffffffff}},
					want: linux.SECCOMP_RET_TRAP,
				},
				{
					desc: "arg disallowed (both arg greater)",
					data: linux.SeccompData{Nr: 1, Arch: LINUX_AUDIT_ARCH, Args: [6]uint64{0x2, 0xffffffff}},
					want: linux.SECCOMP_RET_TRAP,
				},
			},
		},
		{
			name: "MaskedEqual",
			ruleSets: []RuleSet{
				{
					Rules: MakeSyscallRules(map[uintptr]SyscallRule{
						1: PerArg{
							// x & 00000001 00000011 (0x103) == 00000000 00000001 (0x1)
							// Input x must have lowest order bit set and
							// must *not* have 8th or second lowest order bit set.
							MaskedEqual(0x103, 0x1),
						},
					}),
					Action: linux.SECCOMP_RET_ALLOW,
				},
			},
			options: ProgramOptions{
				DefaultAction: linux.SECCOMP_RET_TRAP,
				BadArchAction: linux.SECCOMP_RET_KILL_THREAD,
			},
			specs: []spec{
				{
					desc: "arg allowed (low order mandatory bit)",
					data: linux.SeccompData{
						Nr:   1,
						Arch: LINUX_AUDIT_ARCH,
						// 00000000 00000000 00000000 00000001
						Args: [6]uint64{0x1},
					},
					want: linux.SECCOMP_RET_ALLOW,
				},
				{
					desc: "arg allowed (low order optional bit)",
					data: linux.SeccompData{
						Nr:   1,
						Arch: LINUX_AUDIT_ARCH,
						// 00000000 00000000 00000000 00000101
						Args: [6]uint64{0x5},
					},
					want: linux.SECCOMP_RET_ALLOW,
				},
				{
					desc: "arg disallowed (lowest order bit not set)",
					data: linux.SeccompData{
						Nr:   1,
						Arch: LINUX_AUDIT_ARCH,
						// 00000000 00000000 00000000 00000010
						Args: [6]uint64{0x2},
					},
					want: linux.SECCOMP_RET_TRAP,
				},
				{
					desc: "arg disallowed (second lowest order bit set)",
					data: linux.SeccompData{
						Nr:   1,
						Arch: LINUX_AUDIT_ARCH,
						// 00000000 00000000 00000000 00000011
						Args: [6]uint64{0x3},
					},
					want: linux.SECCOMP_RET_TRAP,
				},
				{
					desc: "arg disallowed (8th bit set)",
					data: linux.SeccompData{
						Nr:   1,
						Arch: LINUX_AUDIT_ARCH,
						// 00000000 00000000 00000001 00000000
						Args: [6]uint64{0x100},
					},
					want: linux.SECCOMP_RET_TRAP,
				},
			},
		},
		{
			name: "NonNegativeFD",
			ruleSets: []RuleSet{
				{
					Rules: MakeSyscallRules(map[uintptr]SyscallRule{
						1: PerArg{
							NonNegativeFD{},
						},
					}),
					Action: linux.SECCOMP_RET_ALLOW,
				},
			},
			options: ProgramOptions{
				DefaultAction: linux.SECCOMP_RET_TRAP,
				BadArchAction: linux.SECCOMP_RET_KILL_THREAD,
			},
			specs: []spec{
				{
					desc: "zero allowed",
					data: linux.SeccompData{Nr: 1, Arch: LINUX_AUDIT_ARCH, Args: [6]uint64{0x0}},
					want: linux.SECCOMP_RET_ALLOW,
				},
				{
					desc: "one allowed",
					data: linux.SeccompData{Nr: 1, Arch: LINUX_AUDIT_ARCH, Args: [6]uint64{0x0}},
					want: linux.SECCOMP_RET_ALLOW,
				},
				{
					desc: "seven allowed",
					data: linux.SeccompData{Nr: 1, Arch: LINUX_AUDIT_ARCH, Args: [6]uint64{0x7}},
					want: linux.SECCOMP_RET_ALLOW,
				},
				{
					desc: "largest int32 allowed",
					data: linux.SeccompData{Nr: 1, Arch: LINUX_AUDIT_ARCH, Args: [6]uint64{0x7fffffff}},
					want: linux.SECCOMP_RET_ALLOW,
				},
				{
					desc: "negative 1 not allowed",
					data: linux.SeccompData{Nr: 1, Arch: LINUX_AUDIT_ARCH, Args: [6]uint64{0x80000000}},
					want: linux.SECCOMP_RET_TRAP,
				},
				{
					desc: "largest uint32 not allowed",
					data: linux.SeccompData{Nr: 1, Arch: LINUX_AUDIT_ARCH, Args: [6]uint64{0xffffffff}},
					want: linux.SECCOMP_RET_TRAP,
				},
				{
					desc: "a positive int64 larger than max uint32 is not allowed",
					data: linux.SeccompData{Nr: 1, Arch: LINUX_AUDIT_ARCH, Args: [6]uint64{0x100000000}},
					want: linux.SECCOMP_RET_TRAP,
				},
				{
					desc: "largest int64 not allowed",
					data: linux.SeccompData{Nr: 1, Arch: LINUX_AUDIT_ARCH, Args: [6]uint64{0x7fffffffffffffff}},
					want: linux.SECCOMP_RET_TRAP,
				},
				{
					desc: "largest uint64 not allowed",
					data: linux.SeccompData{Nr: 1, Arch: LINUX_AUDIT_ARCH, Args: [6]uint64{0xffffffffffffffff}},
					want: linux.SECCOMP_RET_TRAP,
				},
			},
		},
		{
			name: "Instruction Pointer",
			ruleSets: []RuleSet{
				{
					Rules: MakeSyscallRules(map[uintptr]SyscallRule{
						1: PerArg{
							RuleIP: EqualTo(0x7aabbccdd),
						},
					}),
					Action: linux.SECCOMP_RET_ALLOW,
				},
			},
			options: ProgramOptions{
				DefaultAction: linux.SECCOMP_RET_TRAP,
				BadArchAction: linux.SECCOMP_RET_KILL_THREAD,
			},
			specs: []spec{
				{
					desc: "allowed",
					data: linux.SeccompData{Nr: 1, Arch: LINUX_AUDIT_ARCH, Args: [6]uint64{}, InstructionPointer: 0x7aabbccdd},
					want: linux.SECCOMP_RET_ALLOW,
				},
				{
					desc: "disallowed",
					data: linux.SeccompData{Nr: 1, Arch: LINUX_AUDIT_ARCH, Args: [6]uint64{}, InstructionPointer: 0x711223344},
					want: linux.SECCOMP_RET_TRAP,
				},
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			var instrs []bpf.Instruction
			var panicErr any
			func() {
				t.Helper()
				defer func() {
					panicErr = recover()
					t.Helper()
				}()
				var err error
				instrs, _, err = BuildProgram(test.ruleSets, test.options)
				if err != nil {
					t.Fatalf("BuildProgram() got error: %v", err)
				}
			}()
			if test.wantPanic {
				if panicErr == nil {
					t.Fatal("BuildProgram did not panick")
				}
				return
			}
			if panicErr != nil {
				t.Fatalf("BuildProgram unexpectedly panicked: %v", panicErr)
			}
			p, err := bpf.Compile(instrs, true /* optimize */)
			if err != nil {
				t.Fatalf("bpf.Compile got error: %v", err)
			}
			for _, spec := range test.specs {
				got, err := bpf.Exec[bpf.NativeEndian](p, DataAsBPFInput(&spec.data, buf))
				if err != nil {
					t.Fatalf("%s: bpf.Exec got error: %v", spec.desc, err)
				}
				if got != uint32(spec.want) {
					// Include a decoded version of the program in output for debugging purposes.
					decoded, _ := bpf.DecodeInstructions(instrs)
					t.Fatalf("%s: got: %d, want: %d\nBPF Program\n%s", spec.desc, got, spec.want, decoded)
				}
			}
		})
	}
}

// TestRandom tests that randomly generated rules are encoded correctly.
func TestRandom(t *testing.T) {
	rand.Seed(time.Now().UnixNano())
	size := rand.Intn(50) + 1
	syscallRules := NewSyscallRules()
	for syscallRules.Size() < size {
		n := uintptr(rand.Intn(200))
		if !syscallRules.Has(n) {
			syscallRules.Set(n, MatchAll{})
		}
	}

	t.Logf("Testing filters: %v", syscallRules)
	instrs, _, err := BuildProgram([]RuleSet{
		{
			Rules:  syscallRules,
			Action: linux.SECCOMP_RET_ALLOW,
		},
	}, ProgramOptions{
		DefaultAction: linux.SECCOMP_RET_TRAP,
		BadArchAction: linux.SECCOMP_RET_KILL_THREAD,
	})
	if err != nil {
		t.Fatalf("buildProgram() got error: %v", err)
	}
	p, err := bpf.Compile(instrs, true /* optimize */)
	if err != nil {
		t.Fatalf("bpf.Compile got error: %v", err)
	}
	buf := make([]byte, (&linux.SeccompData{}).SizeBytes())
	for i := uint32(0); i < 200; i++ {
		data := linux.SeccompData{Nr: int32(i), Arch: LINUX_AUDIT_ARCH}
		got, err := bpf.Exec[bpf.NativeEndian](p, DataAsBPFInput(&data, buf))
		if err != nil {
			t.Errorf("bpf.Exec got error: %v, for syscall %d", err, i)
			continue
		}
		want := linux.SECCOMP_RET_TRAP
		if syscallRules.Has(uintptr(i)) {
			want = linux.SECCOMP_RET_ALLOW
		}
		if got != uint32(want) {
			t.Errorf("bpf.Exec = %d, want: %d, for syscall %d", got, want, i)
		}
	}
}

// TestReadDeal checks that a process dies when it trips over the filter and
// that it doesn't die when the filter is not triggered.
func TestRealDeal(t *testing.T) {
	for _, test := range []struct {
		name string
		die  bool
		want string
	}{
		{name: "bad syscall", die: true, want: "bad system call"},
		{name: "allowed syscall", die: false, want: "Syscall was allowed!!!"},
	} {
		t.Run(test.name, func(t *testing.T) {
			victim, err := newVictim()
			if err != nil {
				t.Fatalf("unable to get victim: %v", err)
			}
			defer func() {
				if err := os.Remove(victim); err != nil {
					t.Fatalf("Unable to remove victim: %v", err)
				}
			}()

			dieFlag := fmt.Sprintf("-die=%v", test.die)
			cmd := exec.Command(victim, dieFlag)
			out, err := cmd.CombinedOutput()
			if test.die {
				if err == nil {
					t.Fatalf("Victim was not killed as expected, output: %s", out)
				}
				// Depending on kernel version, either RET_TRAP or RET_KILL_PROCESS is
				// used. RET_TRAP dumps reason for exit in output, while RET_KILL_PROCESS
				// returns SIGSYS as exit status.
				if !strings.Contains(string(out), test.want) &&
					!strings.Contains(err.Error(), test.want) {
					t.Fatalf("Victim error is wrong, got: %v, err: %v, want: %v", string(out), err, test.want)
				}
				return
			}
			// test.die is false
			if err != nil {
				t.Logf("out: %s", string(out))
				t.Fatalf("Victim failed to execute, err: %v", err)
			}
			if !strings.Contains(string(out), test.want) {
				t.Fatalf("Victim output is wrong, got: %v, want: %v", string(out), test.want)
			}
		})
	}
}

// TestMerge ensures that empty rules are not erased when rules are merged.
func TestMerge(t *testing.T) {
	for _, tst := range []struct {
		name  string
		main  SyscallRule
		merge SyscallRule
		want  SyscallRule
	}{
		{
			name:  "MatchAll both",
			main:  MatchAll{},
			merge: MatchAll{},
			want:  Or{MatchAll{}, MatchAll{}},
		},
		{
			name:  "MatchAll and Or",
			main:  MatchAll{},
			merge: Or{PerArg{EqualTo(0)}},
			want:  Or{MatchAll{}, Or{PerArg{EqualTo(0)}}},
		},
		{
			name:  "Or and MatchAll",
			main:  Or{PerArg{EqualTo(0)}},
			merge: MatchAll{},
			want:  Or{Or{PerArg{EqualTo(0)}}, MatchAll{}},
		},
		{
			name:  "2 Ors",
			main:  Or{PerArg{EqualTo(0)}},
			merge: Or{PerArg{EqualTo(1)}},
			want:  Or{Or{PerArg{EqualTo(0)}}, Or{PerArg{EqualTo(1)}}},
		},
	} {
		t.Run(tst.name, func(t *testing.T) {
			mainRules := MakeSyscallRules(map[uintptr]SyscallRule{
				1: tst.main,
			}).Merge(MakeSyscallRules(map[uintptr]SyscallRule{
				1: tst.merge,
			}))
			wantRules := MakeSyscallRules(map[uintptr]SyscallRule{1: tst.want})
			if !reflect.DeepEqual(mainRules, wantRules) {
				t.Errorf("got rules:\n%v\nwant rules:\n%v\n", mainRules, wantRules)
			}
		})
	}
}

// TestOptimizeSyscallRule tests the behavior of syscall rule optimizers.
func TestOptimizeSyscallRule(t *testing.T) {
	// av is a shorthand for `AnyValue{}`, used below to keep `PerArg`
	// structs short enough to comfortably fit on one line.
	av := AnyValue{}
	for _, test := range []struct {
		name       string
		rule       SyscallRule
		optimizers []ruleOptimizerFunc
		want       SyscallRule
	}{
		{
			name: "do nothing to a simple rule",
			rule: PerArg{NotEqual(0xff), av, av, av, av, av, av},
			want: PerArg{NotEqual(0xff), av, av, av, av, av, av},
		},
		{
			name: "flatten Or rule",
			rule: Or{
				Or{
					PerArg{EqualTo(0x11)},
					Or{
						PerArg{EqualTo(0x22)},
						PerArg{EqualTo(0x33)},
					},
					PerArg{EqualTo(0x44)},
				},
				Or{
					PerArg{EqualTo(0x55)},
					PerArg{EqualTo(0x66)},
				},
			},
			want: Or{
				PerArg{EqualTo(0x11), av, av, av, av, av, av},
				PerArg{EqualTo(0x22), av, av, av, av, av, av},
				PerArg{EqualTo(0x33), av, av, av, av, av, av},
				PerArg{EqualTo(0x44), av, av, av, av, av, av},
				PerArg{EqualTo(0x55), av, av, av, av, av, av},
				PerArg{EqualTo(0x66), av, av, av, av, av, av},
			},
		},
		{
			name: "flatten And rule",
			rule: And{
				And{
					PerArg{NotEqual(0x11)},
					And{
						PerArg{NotEqual(0x22)},
						PerArg{NotEqual(0x33)},
					},
					PerArg{NotEqual(0x44)},
				},
				And{
					PerArg{NotEqual(0x55)},
					PerArg{NotEqual(0x66)},
				},
			},
			want: And{
				PerArg{NotEqual(0x11), av, av, av, av, av, av},
				PerArg{NotEqual(0x22), av, av, av, av, av, av},
				PerArg{NotEqual(0x33), av, av, av, av, av, av},
				PerArg{NotEqual(0x44), av, av, av, av, av, av},
				PerArg{NotEqual(0x55), av, av, av, av, av, av},
				PerArg{NotEqual(0x66), av, av, av, av, av, av},
			},
		},
		{
			name: "simplify Or with single rule",
			rule: Or{
				PerArg{EqualTo(0x11)},
			},
			want: PerArg{EqualTo(0x11), av, av, av, av, av, av},
		},
		{
			name: "simplify And with single rule",
			rule: And{
				PerArg{EqualTo(0x11)},
			},
			want: PerArg{EqualTo(0x11), av, av, av, av, av, av},
		},
		{
			name: "simplify Or with MatchAll",
			rule: Or{
				PerArg{EqualTo(0x11)},
				Or{
					MatchAll{},
				},
				PerArg{EqualTo(0x22)},
			},
			want: MatchAll{},
		},
		{
			name: "single MatchAll in Or is not an empty rule",
			rule: Or{
				MatchAll{},
				MatchAll{},
			},
			optimizers: []ruleOptimizerFunc{
				convertMatchAllOrXToMatchAll,
			},
			want: MatchAll{},
		},
		{
			name: "simplify And with MatchAll",
			rule: And{
				PerArg{NotEqual(0x11)},
				And{
					MatchAll{},
				},
				PerArg{NotEqual(0x22)},
			},
			want: And{
				PerArg{NotEqual(0x11), av, av, av, av, av, av},
				PerArg{NotEqual(0x22), av, av, av, av, av, av},
			},
		},
		{
			name: "single MatchAll in And is not optimized to an empty rule",
			rule: And{
				MatchAll{},
				MatchAll{},
			},
			optimizers: []ruleOptimizerFunc{
				convertMatchAllAndXToX,
			},
			want: MatchAll{},
		},
		{
			name: "PerArg nil to AnyValue",
			rule: PerArg{av, EqualTo(0)},
			optimizers: []ruleOptimizerFunc{
				nilInPerArgToAnyValue,
			},
			want: PerArg{av, EqualTo(0), av, av, av, av, av},
		},
		{
			name: "Useless PerArg is MatchAll",
			rule: PerArg{av, av},
			optimizers: []ruleOptimizerFunc{
				nilInPerArgToAnyValue,
				convertUselessPerArgToMatchAll,
			},
			want: MatchAll{},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			var got SyscallRule
			if len(test.optimizers) == 0 {
				got = optimizeSyscallRule(test.rule)
			} else {
				got = optimizeSyscallRuleFuncs(test.rule, test.optimizers)
			}
			if !reflect.DeepEqual(got, test.want) {
				t.Errorf("got rule:\n%v\nwant rule:\n%v\n", got, test.want)
			}
		})
	}
}
