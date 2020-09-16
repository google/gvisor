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
	"fmt"
	"io"
	"io/ioutil"
	"math"
	"math/rand"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/binary"
	"gvisor.dev/gvisor/pkg/bpf"
)

type seccompData struct {
	nr                 uint32
	arch               uint32
	instructionPointer uint64
	args               [6]uint64
}

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

// asInput converts a seccompData to a bpf.Input.
func (d *seccompData) asInput() bpf.Input {
	return bpf.InputBytes{binary.Marshal(nil, binary.LittleEndian, d), binary.LittleEndian}
}

func TestBasic(t *testing.T) {
	type spec struct {
		// desc is the test's description.
		desc string

		// data is the input data.
		data seccompData

		// want is the expected return value of the BPF program.
		want linux.BPFAction
	}

	for _, test := range []struct {
		name          string
		ruleSets      []RuleSet
		defaultAction linux.BPFAction
		badArchAction linux.BPFAction
		specs         []spec
	}{
		{
			name: "Single syscall",
			ruleSets: []RuleSet{
				{
					Rules:  SyscallRules{1: {}},
					Action: linux.SECCOMP_RET_ALLOW,
				},
			},
			defaultAction: linux.SECCOMP_RET_TRAP,
			badArchAction: linux.SECCOMP_RET_KILL_THREAD,
			specs: []spec{
				{
					desc: "syscall allowed",
					data: seccompData{nr: 1, arch: LINUX_AUDIT_ARCH},
					want: linux.SECCOMP_RET_ALLOW,
				},
				{
					desc: "syscall disallowed",
					data: seccompData{nr: 2, arch: LINUX_AUDIT_ARCH},
					want: linux.SECCOMP_RET_TRAP,
				},
			},
		},
		{
			name: "Multiple rulesets",
			ruleSets: []RuleSet{
				{
					Rules: SyscallRules{
						1: []Rule{
							{
								EqualTo(0x1),
							},
						},
					},
					Action: linux.SECCOMP_RET_ALLOW,
				},
				{
					Rules: SyscallRules{
						1: {},
						2: {},
					},
					Action: linux.SECCOMP_RET_TRAP,
				},
			},
			defaultAction: linux.SECCOMP_RET_KILL_THREAD,
			badArchAction: linux.SECCOMP_RET_KILL_THREAD,
			specs: []spec{
				{
					desc: "allowed (1a)",
					data: seccompData{nr: 1, arch: LINUX_AUDIT_ARCH, args: [6]uint64{0x1}},
					want: linux.SECCOMP_RET_ALLOW,
				},
				{
					desc: "allowed (1b)",
					data: seccompData{nr: 1, arch: LINUX_AUDIT_ARCH},
					want: linux.SECCOMP_RET_TRAP,
				},
				{
					desc: "syscall 1 matched 2nd rule",
					data: seccompData{nr: 1, arch: LINUX_AUDIT_ARCH},
					want: linux.SECCOMP_RET_TRAP,
				},
				{
					desc: "no match",
					data: seccompData{nr: 0, arch: LINUX_AUDIT_ARCH},
					want: linux.SECCOMP_RET_KILL_THREAD,
				},
			},
		},
		{
			name: "Multiple syscalls",
			ruleSets: []RuleSet{
				{
					Rules: SyscallRules{
						1: {},
						3: {},
						5: {},
					},
					Action: linux.SECCOMP_RET_ALLOW,
				},
			},
			defaultAction: linux.SECCOMP_RET_TRAP,
			badArchAction: linux.SECCOMP_RET_KILL_THREAD,
			specs: []spec{
				{
					desc: "allowed (1)",
					data: seccompData{nr: 1, arch: LINUX_AUDIT_ARCH},
					want: linux.SECCOMP_RET_ALLOW,
				},
				{
					desc: "allowed (3)",
					data: seccompData{nr: 3, arch: LINUX_AUDIT_ARCH},
					want: linux.SECCOMP_RET_ALLOW,
				},
				{
					desc: "allowed (5)",
					data: seccompData{nr: 5, arch: LINUX_AUDIT_ARCH},
					want: linux.SECCOMP_RET_ALLOW,
				},
				{
					desc: "disallowed (0)",
					data: seccompData{nr: 0, arch: LINUX_AUDIT_ARCH},
					want: linux.SECCOMP_RET_TRAP,
				},
				{
					desc: "disallowed (2)",
					data: seccompData{nr: 2, arch: LINUX_AUDIT_ARCH},
					want: linux.SECCOMP_RET_TRAP,
				},
				{
					desc: "disallowed (4)",
					data: seccompData{nr: 4, arch: LINUX_AUDIT_ARCH},
					want: linux.SECCOMP_RET_TRAP,
				},
				{
					desc: "disallowed (6)",
					data: seccompData{nr: 6, arch: LINUX_AUDIT_ARCH},
					want: linux.SECCOMP_RET_TRAP,
				},
				{
					desc: "disallowed (100)",
					data: seccompData{nr: 100, arch: LINUX_AUDIT_ARCH},
					want: linux.SECCOMP_RET_TRAP,
				},
			},
		},
		{
			name: "Wrong architecture",
			ruleSets: []RuleSet{
				{
					Rules: SyscallRules{
						1: {},
					},
					Action: linux.SECCOMP_RET_ALLOW,
				},
			},
			defaultAction: linux.SECCOMP_RET_TRAP,
			badArchAction: linux.SECCOMP_RET_KILL_THREAD,
			specs: []spec{
				{
					desc: "arch (123)",
					data: seccompData{nr: 1, arch: 123},
					want: linux.SECCOMP_RET_KILL_THREAD,
				},
			},
		},
		{
			name: "Syscall disallowed",
			ruleSets: []RuleSet{
				{
					Rules: SyscallRules{
						1: {},
					},
					Action: linux.SECCOMP_RET_ALLOW,
				},
			},
			defaultAction: linux.SECCOMP_RET_TRAP,
			badArchAction: linux.SECCOMP_RET_KILL_THREAD,
			specs: []spec{
				{
					desc: "action trap",
					data: seccompData{nr: 2, arch: LINUX_AUDIT_ARCH},
					want: linux.SECCOMP_RET_TRAP,
				},
			},
		},
		{
			name: "Syscall arguments",
			ruleSets: []RuleSet{
				{
					Rules: SyscallRules{
						1: []Rule{
							{
								MatchAny{},
								EqualTo(0xf),
							},
						},
					},
					Action: linux.SECCOMP_RET_ALLOW,
				},
			},
			defaultAction: linux.SECCOMP_RET_TRAP,
			badArchAction: linux.SECCOMP_RET_KILL_THREAD,
			specs: []spec{
				{
					desc: "allowed",
					data: seccompData{nr: 1, arch: LINUX_AUDIT_ARCH, args: [6]uint64{0xf, 0xf}},
					want: linux.SECCOMP_RET_ALLOW,
				},
				{
					desc: "disallowed",
					data: seccompData{nr: 1, arch: LINUX_AUDIT_ARCH, args: [6]uint64{0xf, 0xe}},
					want: linux.SECCOMP_RET_TRAP,
				},
			},
		},
		{
			name: "Multiple arguments",
			ruleSets: []RuleSet{
				{
					Rules: SyscallRules{
						1: []Rule{
							{
								EqualTo(0xf),
							},
							{
								EqualTo(0xe),
							},
						},
					},
					Action: linux.SECCOMP_RET_ALLOW,
				},
			},
			defaultAction: linux.SECCOMP_RET_TRAP,
			badArchAction: linux.SECCOMP_RET_KILL_THREAD,
			specs: []spec{
				{
					desc: "match first rule",
					data: seccompData{nr: 1, arch: LINUX_AUDIT_ARCH, args: [6]uint64{0xf}},
					want: linux.SECCOMP_RET_ALLOW,
				},
				{
					desc: "match 2nd rule",
					data: seccompData{nr: 1, arch: LINUX_AUDIT_ARCH, args: [6]uint64{0xe}},
					want: linux.SECCOMP_RET_ALLOW,
				},
			},
		},
		{
			name: "EqualTo",
			ruleSets: []RuleSet{
				{
					Rules: SyscallRules{
						1: []Rule{
							{
								EqualTo(0),
								EqualTo(math.MaxUint64 - 1),
								EqualTo(math.MaxUint32),
							},
						},
					},
					Action: linux.SECCOMP_RET_ALLOW,
				},
			},
			defaultAction: linux.SECCOMP_RET_TRAP,
			badArchAction: linux.SECCOMP_RET_KILL_THREAD,
			specs: []spec{
				{
					desc: "argument allowed (all match)",
					data: seccompData{
						nr:   1,
						arch: LINUX_AUDIT_ARCH,
						args: [6]uint64{0, math.MaxUint64 - 1, math.MaxUint32},
					},
					want: linux.SECCOMP_RET_ALLOW,
				},
				{
					desc: "argument disallowed (one mismatch)",
					data: seccompData{
						nr:   1,
						arch: LINUX_AUDIT_ARCH,
						args: [6]uint64{0, math.MaxUint64, math.MaxUint32},
					},
					want: linux.SECCOMP_RET_TRAP,
				},
				{
					desc: "argument disallowed (multiple mismatch)",
					data: seccompData{
						nr:   1,
						arch: LINUX_AUDIT_ARCH,
						args: [6]uint64{0, math.MaxUint64, math.MaxUint32 - 1},
					},
					want: linux.SECCOMP_RET_TRAP,
				},
			},
		},
		{
			name: "NotEqual",
			ruleSets: []RuleSet{
				{
					Rules: SyscallRules{
						1: []Rule{
							{
								NotEqual(0x7aabbccdd),
								NotEqual(math.MaxUint64 - 1),
								NotEqual(math.MaxUint32),
							},
						},
					},
					Action: linux.SECCOMP_RET_ALLOW,
				},
			},
			defaultAction: linux.SECCOMP_RET_TRAP,
			badArchAction: linux.SECCOMP_RET_KILL_THREAD,
			specs: []spec{
				{
					desc: "arg allowed",
					data: seccompData{
						nr:   1,
						arch: LINUX_AUDIT_ARCH,
						args: [6]uint64{0, math.MaxUint64, math.MaxUint32 - 1},
					},
					want: linux.SECCOMP_RET_ALLOW,
				},
				{
					desc: "arg disallowed (one equal)",
					data: seccompData{
						nr:   1,
						arch: LINUX_AUDIT_ARCH,
						args: [6]uint64{0x7aabbccdd, math.MaxUint64, math.MaxUint32 - 1},
					},
					want: linux.SECCOMP_RET_TRAP,
				},
				{
					desc: "arg disallowed (all equal)",
					data: seccompData{
						nr:   1,
						arch: LINUX_AUDIT_ARCH,
						args: [6]uint64{0x7aabbccdd, math.MaxUint64 - 1, math.MaxUint32},
					},
					want: linux.SECCOMP_RET_TRAP,
				},
			},
		},
		{
			name: "GreaterThan",
			ruleSets: []RuleSet{
				{
					Rules: SyscallRules{
						1: []Rule{
							{
								// 4294967298
								// Both upper 32 bits and lower 32 bits are non-zero.
								// 00000000000000000000000000000010
								// 00000000000000000000000000000010
								GreaterThan(0x00000002_00000002),
							},
						},
					},
					Action: linux.SECCOMP_RET_ALLOW,
				},
			},
			defaultAction: linux.SECCOMP_RET_TRAP,
			badArchAction: linux.SECCOMP_RET_KILL_THREAD,
			specs: []spec{
				{
					desc: "high 32bits greater",
					data: seccompData{nr: 1, arch: LINUX_AUDIT_ARCH, args: [6]uint64{0x00000003_00000002}},
					want: linux.SECCOMP_RET_ALLOW,
				},
				{
					desc: "high 32bits equal, low 32bits greater",
					data: seccompData{nr: 1, arch: LINUX_AUDIT_ARCH, args: [6]uint64{0x00000002_00000003}},
					want: linux.SECCOMP_RET_ALLOW,
				},
				{
					desc: "high 32bits equal, low 32bits equal",
					data: seccompData{nr: 1, arch: LINUX_AUDIT_ARCH, args: [6]uint64{0x00000002_00000002}},
					want: linux.SECCOMP_RET_TRAP,
				},
				{
					desc: "high 32bits equal, low 32bits less",
					data: seccompData{nr: 1, arch: LINUX_AUDIT_ARCH, args: [6]uint64{0x00000002_00000001}},
					want: linux.SECCOMP_RET_TRAP,
				},
				{
					desc: "high 32bits less",
					data: seccompData{nr: 1, arch: LINUX_AUDIT_ARCH, args: [6]uint64{0x00000001_00000003}},
					want: linux.SECCOMP_RET_TRAP,
				},
			},
		},
		{
			name: "GreaterThan (multi)",
			ruleSets: []RuleSet{
				{
					Rules: SyscallRules{
						1: []Rule{
							{
								GreaterThan(0xf),
								GreaterThan(0xabcd000d),
							},
						},
					},
					Action: linux.SECCOMP_RET_ALLOW,
				},
			},
			defaultAction: linux.SECCOMP_RET_TRAP,
			badArchAction: linux.SECCOMP_RET_KILL_THREAD,
			specs: []spec{
				{
					desc: "arg allowed",
					data: seccompData{nr: 1, arch: LINUX_AUDIT_ARCH, args: [6]uint64{0x10, 0xffffffff}},
					want: linux.SECCOMP_RET_ALLOW,
				},
				{
					desc: "arg disallowed (first arg equal)",
					data: seccompData{nr: 1, arch: LINUX_AUDIT_ARCH, args: [6]uint64{0xf, 0xffffffff}},
					want: linux.SECCOMP_RET_TRAP,
				},
				{
					desc: "arg disallowed (first arg smaller)",
					data: seccompData{nr: 1, arch: LINUX_AUDIT_ARCH, args: [6]uint64{0x0, 0xffffffff}},
					want: linux.SECCOMP_RET_TRAP,
				},
				{
					desc: "arg disallowed (second arg equal)",
					data: seccompData{nr: 1, arch: LINUX_AUDIT_ARCH, args: [6]uint64{0x10, 0xabcd000d}},
					want: linux.SECCOMP_RET_TRAP,
				},
				{
					desc: "arg disallowed (second arg smaller)",
					data: seccompData{nr: 1, arch: LINUX_AUDIT_ARCH, args: [6]uint64{0x10, 0xa000ffff}},
					want: linux.SECCOMP_RET_TRAP,
				},
			},
		},
		{
			name: "GreaterThanOrEqual",
			ruleSets: []RuleSet{
				{
					Rules: SyscallRules{
						1: []Rule{
							{
								// 4294967298
								// Both upper 32 bits and lower 32 bits are non-zero.
								// 00000000000000000000000000000010
								// 00000000000000000000000000000010
								GreaterThanOrEqual(0x00000002_00000002),
							},
						},
					},
					Action: linux.SECCOMP_RET_ALLOW,
				},
			},
			defaultAction: linux.SECCOMP_RET_TRAP,
			badArchAction: linux.SECCOMP_RET_KILL_THREAD,
			specs: []spec{
				{
					desc: "high 32bits greater",
					data: seccompData{nr: 1, arch: LINUX_AUDIT_ARCH, args: [6]uint64{0x00000003_00000002}},
					want: linux.SECCOMP_RET_ALLOW,
				},
				{
					desc: "high 32bits equal, low 32bits greater",
					data: seccompData{nr: 1, arch: LINUX_AUDIT_ARCH, args: [6]uint64{0x00000002_00000003}},
					want: linux.SECCOMP_RET_ALLOW,
				},
				{
					desc: "high 32bits equal, low 32bits equal",
					data: seccompData{nr: 1, arch: LINUX_AUDIT_ARCH, args: [6]uint64{0x00000002_00000002}},
					want: linux.SECCOMP_RET_ALLOW,
				},
				{
					desc: "high 32bits equal, low 32bits less",
					data: seccompData{nr: 1, arch: LINUX_AUDIT_ARCH, args: [6]uint64{0x00000002_00000001}},
					want: linux.SECCOMP_RET_TRAP,
				},
				{
					desc: "high 32bits less",
					data: seccompData{nr: 1, arch: LINUX_AUDIT_ARCH, args: [6]uint64{0x00000001_00000002}},
					want: linux.SECCOMP_RET_TRAP,
				},
			},
		},
		{
			name: "GreaterThanOrEqual (multi)",
			ruleSets: []RuleSet{
				{
					Rules: SyscallRules{
						1: []Rule{
							{
								GreaterThanOrEqual(0xf),
								GreaterThanOrEqual(0xabcd000d),
							},
						},
					},
					Action: linux.SECCOMP_RET_ALLOW,
				},
			},
			defaultAction: linux.SECCOMP_RET_TRAP,
			badArchAction: linux.SECCOMP_RET_KILL_THREAD,
			specs: []spec{
				{
					desc: "arg allowed (both greater)",
					data: seccompData{nr: 1, arch: LINUX_AUDIT_ARCH, args: [6]uint64{0x10, 0xffffffff}},
					want: linux.SECCOMP_RET_ALLOW,
				},
				{
					desc: "arg allowed (first arg equal)",
					data: seccompData{nr: 1, arch: LINUX_AUDIT_ARCH, args: [6]uint64{0xf, 0xffffffff}},
					want: linux.SECCOMP_RET_ALLOW,
				},
				{
					desc: "arg disallowed (first arg smaller)",
					data: seccompData{nr: 1, arch: LINUX_AUDIT_ARCH, args: [6]uint64{0x0, 0xffffffff}},
					want: linux.SECCOMP_RET_TRAP,
				},
				{
					desc: "arg allowed (second arg equal)",
					data: seccompData{nr: 1, arch: LINUX_AUDIT_ARCH, args: [6]uint64{0x10, 0xabcd000d}},
					want: linux.SECCOMP_RET_ALLOW,
				},
				{
					desc: "arg disallowed (second arg smaller)",
					data: seccompData{nr: 1, arch: LINUX_AUDIT_ARCH, args: [6]uint64{0x10, 0xa000ffff}},
					want: linux.SECCOMP_RET_TRAP,
				},
				{
					desc: "arg disallowed (both arg smaller)",
					data: seccompData{nr: 1, arch: LINUX_AUDIT_ARCH, args: [6]uint64{0x0, 0xa000ffff}},
					want: linux.SECCOMP_RET_TRAP,
				},
			},
		},
		{
			name: "LessThan",
			ruleSets: []RuleSet{
				{
					Rules: SyscallRules{
						1: []Rule{
							{
								// 4294967298
								// Both upper 32 bits and lower 32 bits are non-zero.
								// 00000000000000000000000000000010
								// 00000000000000000000000000000010
								LessThan(0x00000002_00000002),
							},
						},
					},
					Action: linux.SECCOMP_RET_ALLOW,
				},
			},
			defaultAction: linux.SECCOMP_RET_TRAP,
			badArchAction: linux.SECCOMP_RET_KILL_THREAD,
			specs: []spec{
				{
					desc: "high 32bits greater",
					data: seccompData{nr: 1, arch: LINUX_AUDIT_ARCH, args: [6]uint64{0x00000003_00000002}},
					want: linux.SECCOMP_RET_TRAP,
				},
				{
					desc: "high 32bits equal, low 32bits greater",
					data: seccompData{nr: 1, arch: LINUX_AUDIT_ARCH, args: [6]uint64{0x00000002_00000003}},
					want: linux.SECCOMP_RET_TRAP,
				},
				{
					desc: "high 32bits equal, low 32bits equal",
					data: seccompData{nr: 1, arch: LINUX_AUDIT_ARCH, args: [6]uint64{0x00000002_00000002}},
					want: linux.SECCOMP_RET_TRAP,
				},
				{
					desc: "high 32bits equal, low 32bits less",
					data: seccompData{nr: 1, arch: LINUX_AUDIT_ARCH, args: [6]uint64{0x00000002_00000001}},
					want: linux.SECCOMP_RET_ALLOW,
				},
				{
					desc: "high 32bits less",
					data: seccompData{nr: 1, arch: LINUX_AUDIT_ARCH, args: [6]uint64{0x00000001_00000002}},
					want: linux.SECCOMP_RET_ALLOW,
				},
			},
		},
		{
			name: "LessThan (multi)",
			ruleSets: []RuleSet{
				{
					Rules: SyscallRules{
						1: []Rule{
							{
								LessThan(0x1),
								LessThan(0xabcd000d),
							},
						},
					},
					Action: linux.SECCOMP_RET_ALLOW,
				},
			},
			defaultAction: linux.SECCOMP_RET_TRAP,
			badArchAction: linux.SECCOMP_RET_KILL_THREAD,
			specs: []spec{
				{
					desc: "arg allowed",
					data: seccompData{nr: 1, arch: LINUX_AUDIT_ARCH, args: [6]uint64{0x0, 0x0}},
					want: linux.SECCOMP_RET_ALLOW,
				},
				{
					desc: "arg disallowed (first arg equal)",
					data: seccompData{nr: 1, arch: LINUX_AUDIT_ARCH, args: [6]uint64{0x1, 0x0}},
					want: linux.SECCOMP_RET_TRAP,
				},
				{
					desc: "arg disallowed (first arg greater)",
					data: seccompData{nr: 1, arch: LINUX_AUDIT_ARCH, args: [6]uint64{0x2, 0x0}},
					want: linux.SECCOMP_RET_TRAP,
				},
				{
					desc: "arg disallowed (second arg equal)",
					data: seccompData{nr: 1, arch: LINUX_AUDIT_ARCH, args: [6]uint64{0x0, 0xabcd000d}},
					want: linux.SECCOMP_RET_TRAP,
				},
				{
					desc: "arg disallowed (second arg greater)",
					data: seccompData{nr: 1, arch: LINUX_AUDIT_ARCH, args: [6]uint64{0x0, 0xffffffff}},
					want: linux.SECCOMP_RET_TRAP,
				},
				{
					desc: "arg disallowed (both arg greater)",
					data: seccompData{nr: 1, arch: LINUX_AUDIT_ARCH, args: [6]uint64{0x2, 0xffffffff}},
					want: linux.SECCOMP_RET_TRAP,
				},
			},
		},
		{
			name: "LessThanOrEqual",
			ruleSets: []RuleSet{
				{
					Rules: SyscallRules{
						1: []Rule{
							{
								// 4294967298
								// Both upper 32 bits and lower 32 bits are non-zero.
								// 00000000000000000000000000000010
								// 00000000000000000000000000000010
								LessThanOrEqual(0x00000002_00000002),
							},
						},
					},
					Action: linux.SECCOMP_RET_ALLOW,
				},
			},
			defaultAction: linux.SECCOMP_RET_TRAP,
			badArchAction: linux.SECCOMP_RET_KILL_THREAD,
			specs: []spec{
				{
					desc: "high 32bits greater",
					data: seccompData{nr: 1, arch: LINUX_AUDIT_ARCH, args: [6]uint64{0x00000003_00000002}},
					want: linux.SECCOMP_RET_TRAP,
				},
				{
					desc: "high 32bits equal, low 32bits greater",
					data: seccompData{nr: 1, arch: LINUX_AUDIT_ARCH, args: [6]uint64{0x00000002_00000003}},
					want: linux.SECCOMP_RET_TRAP,
				},
				{
					desc: "high 32bits equal, low 32bits equal",
					data: seccompData{nr: 1, arch: LINUX_AUDIT_ARCH, args: [6]uint64{0x00000002_00000002}},
					want: linux.SECCOMP_RET_ALLOW,
				},
				{
					desc: "high 32bits equal, low 32bits less",
					data: seccompData{nr: 1, arch: LINUX_AUDIT_ARCH, args: [6]uint64{0x00000002_00000001}},
					want: linux.SECCOMP_RET_ALLOW,
				},
				{
					desc: "high 32bits less",
					data: seccompData{nr: 1, arch: LINUX_AUDIT_ARCH, args: [6]uint64{0x00000001_00000002}},
					want: linux.SECCOMP_RET_ALLOW,
				},
			},
		},

		{
			name: "LessThanOrEqual (multi)",
			ruleSets: []RuleSet{
				{
					Rules: SyscallRules{
						1: []Rule{
							{
								LessThanOrEqual(0x1),
								LessThanOrEqual(0xabcd000d),
							},
						},
					},
					Action: linux.SECCOMP_RET_ALLOW,
				},
			},
			defaultAction: linux.SECCOMP_RET_TRAP,
			badArchAction: linux.SECCOMP_RET_KILL_THREAD,
			specs: []spec{
				{
					desc: "arg allowed",
					data: seccompData{nr: 1, arch: LINUX_AUDIT_ARCH, args: [6]uint64{0x0, 0x0}},
					want: linux.SECCOMP_RET_ALLOW,
				},
				{
					desc: "arg allowed (first arg equal)",
					data: seccompData{nr: 1, arch: LINUX_AUDIT_ARCH, args: [6]uint64{0x1, 0x0}},
					want: linux.SECCOMP_RET_ALLOW,
				},
				{
					desc: "arg disallowed (first arg greater)",
					data: seccompData{nr: 1, arch: LINUX_AUDIT_ARCH, args: [6]uint64{0x2, 0x0}},
					want: linux.SECCOMP_RET_TRAP,
				},
				{
					desc: "arg allowed (second arg equal)",
					data: seccompData{nr: 1, arch: LINUX_AUDIT_ARCH, args: [6]uint64{0x0, 0xabcd000d}},
					want: linux.SECCOMP_RET_ALLOW,
				},
				{
					desc: "arg disallowed (second arg greater)",
					data: seccompData{nr: 1, arch: LINUX_AUDIT_ARCH, args: [6]uint64{0x0, 0xffffffff}},
					want: linux.SECCOMP_RET_TRAP,
				},
				{
					desc: "arg disallowed (both arg greater)",
					data: seccompData{nr: 1, arch: LINUX_AUDIT_ARCH, args: [6]uint64{0x2, 0xffffffff}},
					want: linux.SECCOMP_RET_TRAP,
				},
			},
		},
		{
			name: "MaskedEqual",
			ruleSets: []RuleSet{
				{
					Rules: SyscallRules{
						1: []Rule{
							{
								// x & 00000001 00000011 (0x103) == 00000000 00000001 (0x1)
								// Input x must have lowest order bit set and
								// must *not* have 8th or second lowest order bit set.
								MaskedEqual(0x103, 0x1),
							},
						},
					},
					Action: linux.SECCOMP_RET_ALLOW,
				},
			},
			defaultAction: linux.SECCOMP_RET_TRAP,
			badArchAction: linux.SECCOMP_RET_KILL_THREAD,
			specs: []spec{
				{
					desc: "arg allowed (low order mandatory bit)",
					data: seccompData{
						nr:   1,
						arch: LINUX_AUDIT_ARCH,
						// 00000000 00000000 00000000 00000001
						args: [6]uint64{0x1},
					},
					want: linux.SECCOMP_RET_ALLOW,
				},
				{
					desc: "arg allowed (low order optional bit)",
					data: seccompData{
						nr:   1,
						arch: LINUX_AUDIT_ARCH,
						// 00000000 00000000 00000000 00000101
						args: [6]uint64{0x5},
					},
					want: linux.SECCOMP_RET_ALLOW,
				},
				{
					desc: "arg disallowed (lowest order bit not set)",
					data: seccompData{
						nr:   1,
						arch: LINUX_AUDIT_ARCH,
						// 00000000 00000000 00000000 00000010
						args: [6]uint64{0x2},
					},
					want: linux.SECCOMP_RET_TRAP,
				},
				{
					desc: "arg disallowed (second lowest order bit set)",
					data: seccompData{
						nr:   1,
						arch: LINUX_AUDIT_ARCH,
						// 00000000 00000000 00000000 00000011
						args: [6]uint64{0x3},
					},
					want: linux.SECCOMP_RET_TRAP,
				},
				{
					desc: "arg disallowed (8th bit set)",
					data: seccompData{
						nr:   1,
						arch: LINUX_AUDIT_ARCH,
						// 00000000 00000000 00000001 00000000
						args: [6]uint64{0x100},
					},
					want: linux.SECCOMP_RET_TRAP,
				},
			},
		},
		{
			name: "Instruction Pointer",
			ruleSets: []RuleSet{
				{
					Rules: SyscallRules{
						1: []Rule{
							{
								RuleIP: EqualTo(0x7aabbccdd),
							},
						},
					},
					Action: linux.SECCOMP_RET_ALLOW,
				},
			},
			defaultAction: linux.SECCOMP_RET_TRAP,
			badArchAction: linux.SECCOMP_RET_KILL_THREAD,
			specs: []spec{
				{
					desc: "allowed",
					data: seccompData{nr: 1, arch: LINUX_AUDIT_ARCH, args: [6]uint64{}, instructionPointer: 0x7aabbccdd},
					want: linux.SECCOMP_RET_ALLOW,
				},
				{
					desc: "disallowed",
					data: seccompData{nr: 1, arch: LINUX_AUDIT_ARCH, args: [6]uint64{}, instructionPointer: 0x711223344},
					want: linux.SECCOMP_RET_TRAP,
				},
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			instrs, err := BuildProgram(test.ruleSets, test.defaultAction, test.badArchAction)
			if err != nil {
				t.Fatalf("BuildProgram() got error: %v", err)
			}
			p, err := bpf.Compile(instrs)
			if err != nil {
				t.Fatalf("bpf.Compile() got error: %v", err)
			}
			for _, spec := range test.specs {
				got, err := bpf.Exec(p, spec.data.asInput())
				if err != nil {
					t.Fatalf("%s: bpf.Exec() got error: %v", spec.desc, err)
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
	syscallRules := make(map[uintptr][]Rule)
	for len(syscallRules) < size {
		n := uintptr(rand.Intn(200))
		if _, ok := syscallRules[n]; !ok {
			syscallRules[n] = []Rule{}
		}
	}

	t.Logf("Testing filters: %v", syscallRules)
	instrs, err := BuildProgram([]RuleSet{
		RuleSet{
			Rules:  syscallRules,
			Action: linux.SECCOMP_RET_ALLOW,
		},
	}, linux.SECCOMP_RET_TRAP, linux.SECCOMP_RET_KILL_THREAD)
	if err != nil {
		t.Fatalf("buildProgram() got error: %v", err)
	}
	p, err := bpf.Compile(instrs)
	if err != nil {
		t.Fatalf("bpf.Compile() got error: %v", err)
	}
	for i := uint32(0); i < 200; i++ {
		data := seccompData{nr: i, arch: LINUX_AUDIT_ARCH}
		got, err := bpf.Exec(p, data.asInput())
		if err != nil {
			t.Errorf("bpf.Exec() got error: %v, for syscall %d", err, i)
			continue
		}
		want := linux.SECCOMP_RET_TRAP
		if _, ok := syscallRules[uintptr(i)]; ok {
			want = linux.SECCOMP_RET_ALLOW
		}
		if got != uint32(want) {
			t.Errorf("bpf.Exec() = %d, want: %d, for syscall %d", got, want, i)
		}
	}
}

// TestReadDeal checks that a process dies when it trips over the filter and
// that it doesn't die when the filter is not triggered.
func TestRealDeal(t *testing.T) {
	for _, test := range []struct {
		die  bool
		want string
	}{
		{die: true, want: "bad system call"},
		{die: false, want: "Syscall was allowed!!!"},
	} {
		victim, err := newVictim()
		if err != nil {
			t.Fatalf("unable to get victim: %v", err)
		}
		defer os.Remove(victim)
		dieFlag := fmt.Sprintf("-die=%v", test.die)
		cmd := exec.Command(victim, dieFlag)

		out, err := cmd.CombinedOutput()
		if test.die {
			if err == nil {
				t.Errorf("victim was not killed as expected, output: %s", out)
				continue
			}
			// Depending on kernel version, either RET_TRAP or RET_KILL_PROCESS is
			// used. RET_TRAP dumps reason for exit in output, while RET_KILL_PROCESS
			// returns SIGSYS as exit status.
			if !strings.Contains(string(out), test.want) &&
				!strings.Contains(err.Error(), test.want) {
				t.Errorf("Victim error is wrong, got: %v, err: %v, want: %v", string(out), err, test.want)
				continue
			}
		} else {
			if err != nil {
				t.Errorf("victim failed to execute, err: %v", err)
				continue
			}
			if !strings.Contains(string(out), test.want) {
				t.Errorf("Victim output is wrong, got: %v, want: %v", string(out), test.want)
				continue
			}
		}
	}
}

// TestMerge ensures that empty rules are not erased when rules are merged.
func TestMerge(t *testing.T) {
	for _, tst := range []struct {
		name  string
		main  []Rule
		merge []Rule
		want  []Rule
	}{
		{
			name:  "empty both",
			main:  nil,
			merge: nil,
			want:  []Rule{{}, {}},
		},
		{
			name:  "empty main",
			main:  nil,
			merge: []Rule{{}},
			want:  []Rule{{}, {}},
		},
		{
			name:  "empty merge",
			main:  []Rule{{}},
			merge: nil,
			want:  []Rule{{}, {}},
		},
	} {
		t.Run(tst.name, func(t *testing.T) {
			mainRules := SyscallRules{1: tst.main}
			mergeRules := SyscallRules{1: tst.merge}
			mainRules.Merge(mergeRules)
			if got, want := len(mainRules[1]), len(tst.want); got != want {
				t.Errorf("wrong length, got: %d, want: %d", got, want)
			}
			for i, r := range mainRules[1] {
				if r != tst.want[i] {
					t.Errorf("result, got: %v, want: %v", r, tst.want[i])
				}
			}
		})
	}
}

// TestAddRule ensures that empty rules are not erased when rules are added.
func TestAddRule(t *testing.T) {
	rules := SyscallRules{1: {}}
	rules.AddRule(1, Rule{})
	if got, want := len(rules[1]), 2; got != want {
		t.Errorf("len(rules[1]), got: %d, want: %d", got, want)
	}
}
