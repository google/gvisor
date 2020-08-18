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
		ruleSets      []RuleSet
		defaultAction linux.BPFAction
		specs         []spec
	}{
		{
			ruleSets: []RuleSet{
				{
					Rules:  SyscallRules{1: {}},
					Action: linux.SECCOMP_RET_ALLOW,
				},
			},
			defaultAction: linux.SECCOMP_RET_TRAP,
			specs: []spec{
				{
					desc: "Single syscall allowed",
					data: seccompData{nr: 1, arch: LINUX_AUDIT_ARCH},
					want: linux.SECCOMP_RET_ALLOW,
				},
				{
					desc: "Single syscall disallowed",
					data: seccompData{nr: 2, arch: LINUX_AUDIT_ARCH},
					want: linux.SECCOMP_RET_TRAP,
				},
			},
		},
		{
			ruleSets: []RuleSet{
				{
					Rules: SyscallRules{
						1: []Rule{
							{
								AllowValue(0x1),
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
			specs: []spec{
				{
					desc: "Multiple rulesets allowed (1a)",
					data: seccompData{nr: 1, arch: LINUX_AUDIT_ARCH, args: [6]uint64{0x1}},
					want: linux.SECCOMP_RET_ALLOW,
				},
				{
					desc: "Multiple rulesets allowed (1b)",
					data: seccompData{nr: 1, arch: LINUX_AUDIT_ARCH},
					want: linux.SECCOMP_RET_TRAP,
				},
				{
					desc: "Multiple rulesets allowed (2)",
					data: seccompData{nr: 1, arch: LINUX_AUDIT_ARCH},
					want: linux.SECCOMP_RET_TRAP,
				},
				{
					desc: "Multiple rulesets allowed (2)",
					data: seccompData{nr: 0, arch: LINUX_AUDIT_ARCH},
					want: linux.SECCOMP_RET_KILL_THREAD,
				},
			},
		},
		{
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
			specs: []spec{
				{
					desc: "Multiple syscalls allowed (1)",
					data: seccompData{nr: 1, arch: LINUX_AUDIT_ARCH},
					want: linux.SECCOMP_RET_ALLOW,
				},
				{
					desc: "Multiple syscalls allowed (3)",
					data: seccompData{nr: 3, arch: LINUX_AUDIT_ARCH},
					want: linux.SECCOMP_RET_ALLOW,
				},
				{
					desc: "Multiple syscalls allowed (5)",
					data: seccompData{nr: 5, arch: LINUX_AUDIT_ARCH},
					want: linux.SECCOMP_RET_ALLOW,
				},
				{
					desc: "Multiple syscalls disallowed (0)",
					data: seccompData{nr: 0, arch: LINUX_AUDIT_ARCH},
					want: linux.SECCOMP_RET_TRAP,
				},
				{
					desc: "Multiple syscalls disallowed (2)",
					data: seccompData{nr: 2, arch: LINUX_AUDIT_ARCH},
					want: linux.SECCOMP_RET_TRAP,
				},
				{
					desc: "Multiple syscalls disallowed (4)",
					data: seccompData{nr: 4, arch: LINUX_AUDIT_ARCH},
					want: linux.SECCOMP_RET_TRAP,
				},
				{
					desc: "Multiple syscalls disallowed (6)",
					data: seccompData{nr: 6, arch: LINUX_AUDIT_ARCH},
					want: linux.SECCOMP_RET_TRAP,
				},
				{
					desc: "Multiple syscalls disallowed (100)",
					data: seccompData{nr: 100, arch: LINUX_AUDIT_ARCH},
					want: linux.SECCOMP_RET_TRAP,
				},
			},
		},
		{
			ruleSets: []RuleSet{
				{
					Rules: SyscallRules{
						1: {},
					},
					Action: linux.SECCOMP_RET_ALLOW,
				},
			},
			defaultAction: linux.SECCOMP_RET_TRAP,
			specs: []spec{
				{
					desc: "Wrong architecture",
					data: seccompData{nr: 1, arch: 123},
					want: linux.SECCOMP_RET_TRAP,
				},
			},
		},
		{
			ruleSets: []RuleSet{
				{
					Rules: SyscallRules{
						1: {},
					},
					Action: linux.SECCOMP_RET_ALLOW,
				},
			},
			defaultAction: linux.SECCOMP_RET_TRAP,
			specs: []spec{
				{
					desc: "Syscall disallowed, action trap",
					data: seccompData{nr: 2, arch: LINUX_AUDIT_ARCH},
					want: linux.SECCOMP_RET_TRAP,
				},
			},
		},
		{
			ruleSets: []RuleSet{
				{
					Rules: SyscallRules{
						1: []Rule{
							{
								AllowAny{},
								AllowValue(0xf),
							},
						},
					},
					Action: linux.SECCOMP_RET_ALLOW,
				},
			},
			defaultAction: linux.SECCOMP_RET_TRAP,
			specs: []spec{
				{
					desc: "Syscall argument allowed",
					data: seccompData{nr: 1, arch: LINUX_AUDIT_ARCH, args: [6]uint64{0xf, 0xf}},
					want: linux.SECCOMP_RET_ALLOW,
				},
				{
					desc: "Syscall argument disallowed",
					data: seccompData{nr: 1, arch: LINUX_AUDIT_ARCH, args: [6]uint64{0xf, 0xe}},
					want: linux.SECCOMP_RET_TRAP,
				},
			},
		},
		{
			ruleSets: []RuleSet{
				{
					Rules: SyscallRules{
						1: []Rule{
							{
								AllowValue(0xf),
							},
							{
								AllowValue(0xe),
							},
						},
					},
					Action: linux.SECCOMP_RET_ALLOW,
				},
			},
			defaultAction: linux.SECCOMP_RET_TRAP,
			specs: []spec{
				{
					desc: "Syscall argument allowed, two rules",
					data: seccompData{nr: 1, arch: LINUX_AUDIT_ARCH, args: [6]uint64{0xf}},
					want: linux.SECCOMP_RET_ALLOW,
				},
				{
					desc: "Syscall argument allowed, two rules",
					data: seccompData{nr: 1, arch: LINUX_AUDIT_ARCH, args: [6]uint64{0xe}},
					want: linux.SECCOMP_RET_ALLOW,
				},
			},
		},
		{
			ruleSets: []RuleSet{
				{
					Rules: SyscallRules{
						1: []Rule{
							{
								AllowValue(0),
								AllowValue(math.MaxUint64 - 1),
								AllowValue(math.MaxUint32),
							},
						},
					},
					Action: linux.SECCOMP_RET_ALLOW,
				},
			},
			defaultAction: linux.SECCOMP_RET_TRAP,
			specs: []spec{
				{
					desc: "64bit syscall argument allowed",
					data: seccompData{
						nr:   1,
						arch: LINUX_AUDIT_ARCH,
						args: [6]uint64{0, math.MaxUint64 - 1, math.MaxUint32},
					},
					want: linux.SECCOMP_RET_ALLOW,
				},
				{
					desc: "64bit syscall argument disallowed",
					data: seccompData{
						nr:   1,
						arch: LINUX_AUDIT_ARCH,
						args: [6]uint64{0, math.MaxUint64, math.MaxUint32},
					},
					want: linux.SECCOMP_RET_TRAP,
				},
				{
					desc: "64bit syscall argument disallowed",
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
			specs: []spec{
				{
					desc: "GreaterThan: Syscall argument allowed",
					data: seccompData{nr: 1, arch: LINUX_AUDIT_ARCH, args: [6]uint64{0x10, 0xffffffff}},
					want: linux.SECCOMP_RET_ALLOW,
				},
				{
					desc: "GreaterThan: Syscall argument disallowed (equal)",
					data: seccompData{nr: 1, arch: LINUX_AUDIT_ARCH, args: [6]uint64{0xf, 0xffffffff}},
					want: linux.SECCOMP_RET_TRAP,
				},
				{
					desc: "Syscall argument disallowed (smaller)",
					data: seccompData{nr: 1, arch: LINUX_AUDIT_ARCH, args: [6]uint64{0x0, 0xffffffff}},
					want: linux.SECCOMP_RET_TRAP,
				},
				{
					desc: "GreaterThan2: Syscall argument allowed",
					data: seccompData{nr: 1, arch: LINUX_AUDIT_ARCH, args: [6]uint64{0x10, 0xfbcd000d}},
					want: linux.SECCOMP_RET_ALLOW,
				},
				{
					desc: "GreaterThan2: Syscall argument disallowed (equal)",
					data: seccompData{nr: 1, arch: LINUX_AUDIT_ARCH, args: [6]uint64{0x10, 0xabcd000d}},
					want: linux.SECCOMP_RET_TRAP,
				},
				{
					desc: "GreaterThan2: Syscall argument disallowed (smaller)",
					data: seccompData{nr: 1, arch: LINUX_AUDIT_ARCH, args: [6]uint64{0x10, 0xa000ffff}},
					want: linux.SECCOMP_RET_TRAP,
				},
			},
		},
		{
			ruleSets: []RuleSet{
				{
					Rules: SyscallRules{
						1: []Rule{
							{
								RuleIP: AllowValue(0x7aabbccdd),
							},
						},
					},
					Action: linux.SECCOMP_RET_ALLOW,
				},
			},
			defaultAction: linux.SECCOMP_RET_TRAP,
			specs: []spec{
				{
					desc: "IP: Syscall instruction pointer allowed",
					data: seccompData{nr: 1, arch: LINUX_AUDIT_ARCH, args: [6]uint64{}, instructionPointer: 0x7aabbccdd},
					want: linux.SECCOMP_RET_ALLOW,
				},
				{
					desc: "IP: Syscall instruction pointer disallowed",
					data: seccompData{nr: 1, arch: LINUX_AUDIT_ARCH, args: [6]uint64{}, instructionPointer: 0x711223344},
					want: linux.SECCOMP_RET_TRAP,
				},
			},
		},
	} {
		instrs, err := BuildProgram(test.ruleSets, test.defaultAction)
		if err != nil {
			t.Errorf("%s: buildProgram() got error: %v", test.specs[0].desc, err)
			continue
		}
		p, err := bpf.Compile(instrs)
		if err != nil {
			t.Errorf("%s: bpf.Compile() got error: %v", test.specs[0].desc, err)
			continue
		}
		for _, spec := range test.specs {
			got, err := bpf.Exec(p, spec.data.asInput())
			if err != nil {
				t.Errorf("%s: bpf.Exec() got error: %v", spec.desc, err)
				continue
			}
			if got != uint32(spec.want) {
				t.Errorf("%s: bpd.Exec() = %d, want: %d", spec.desc, got, spec.want)
			}
		}
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
	}, linux.SECCOMP_RET_TRAP)
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
