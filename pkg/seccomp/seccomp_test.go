// Copyright 2018 Google Inc.
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
	"math/rand"
	"os"
	"os/exec"
	"sort"
	"strings"
	"testing"
	"time"

	"gvisor.googlesource.com/gvisor/pkg/abi/linux"
	"gvisor.googlesource.com/gvisor/pkg/binary"
	"gvisor.googlesource.com/gvisor/pkg/bpf"
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
		want uint32
	}

	for _, test := range []struct {
		// filters are the set of syscall that are allowed.
		filters []uintptr
		kill    bool
		specs   []spec
	}{
		{
			filters: []uintptr{1},
			kill:    false,
			specs: []spec{
				{
					desc: "Single syscall allowed",
					data: seccompData{nr: 1, arch: linux.AUDIT_ARCH_X86_64},
					want: linux.SECCOMP_RET_ALLOW,
				},
				{
					desc: "Single syscall disallowed",
					data: seccompData{nr: 2, arch: linux.AUDIT_ARCH_X86_64},
					want: linux.SECCOMP_RET_TRAP,
				},
			},
		},
		{
			filters: []uintptr{1, 3, 5},
			kill:    false,
			specs: []spec{
				{
					desc: "Multiple syscalls allowed (1)",
					data: seccompData{nr: 1, arch: linux.AUDIT_ARCH_X86_64},
					want: linux.SECCOMP_RET_ALLOW,
				},
				{
					desc: "Multiple syscalls allowed (3)",
					data: seccompData{nr: 3, arch: linux.AUDIT_ARCH_X86_64},
					want: linux.SECCOMP_RET_ALLOW,
				},
				{
					desc: "Multiple syscalls allowed (5)",
					data: seccompData{nr: 5, arch: linux.AUDIT_ARCH_X86_64},
					want: linux.SECCOMP_RET_ALLOW,
				},
				{
					desc: "Multiple syscalls disallowed (0)",
					data: seccompData{nr: 0, arch: linux.AUDIT_ARCH_X86_64},
					want: linux.SECCOMP_RET_TRAP,
				},
				{
					desc: "Multiple syscalls disallowed (2)",
					data: seccompData{nr: 2, arch: linux.AUDIT_ARCH_X86_64},
					want: linux.SECCOMP_RET_TRAP,
				},
				{
					desc: "Multiple syscalls disallowed (4)",
					data: seccompData{nr: 4, arch: linux.AUDIT_ARCH_X86_64},
					want: linux.SECCOMP_RET_TRAP,
				},
				{
					desc: "Multiple syscalls disallowed (6)",
					data: seccompData{nr: 6, arch: linux.AUDIT_ARCH_X86_64},
					want: linux.SECCOMP_RET_TRAP,
				},
				{
					desc: "Multiple syscalls disallowed (100)",
					data: seccompData{nr: 100, arch: linux.AUDIT_ARCH_X86_64},
					want: linux.SECCOMP_RET_TRAP,
				},
			},
		},
		{
			filters: []uintptr{1},
			kill:    false,
			specs: []spec{
				{
					desc: "Wrong architecture",
					data: seccompData{nr: 1, arch: 123},
					want: linux.SECCOMP_RET_TRAP,
				},
			},
		},
		{
			filters: []uintptr{1},
			kill:    true,
			specs: []spec{
				{
					desc: "Syscall disallowed, action kill",
					data: seccompData{nr: 2, arch: linux.AUDIT_ARCH_X86_64},
					want: linux.SECCOMP_RET_KILL,
				},
			},
		},
	} {
		sort.Slice(test.filters, func(i, j int) bool { return test.filters[i] < test.filters[j] })
		instrs, err := buildProgram(test.filters, test.kill)
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
			if got != spec.want {
				t.Errorf("%s: bpd.Exec() = %d, want: %d", spec.desc, got, spec.want)
			}
		}
	}
}

func TestRandom(t *testing.T) {
	rand.Seed(time.Now().UnixNano())
	size := rand.Intn(50) + 1
	syscalls := make([]uintptr, 0, size)
	syscallMap := make(map[uintptr]struct{})
	for len(syscalls) < size {
		n := uintptr(rand.Intn(200))
		if _, ok := syscallMap[n]; !ok {
			syscalls = append(syscalls, n)
			syscallMap[n] = struct{}{}
		}
	}

	sort.Slice(syscalls, func(i, j int) bool { return syscalls[i] < syscalls[j] })
	fmt.Printf("Testing filters: %v", syscalls)
	instrs, err := buildProgram(syscalls, false)
	if err != nil {
		t.Fatalf("buildProgram() got error: %v", err)
	}
	p, err := bpf.Compile(instrs)
	if err != nil {
		t.Fatalf("bpf.Compile() got error: %v", err)
	}
	for i := uint32(0); i < 200; i++ {
		data := seccompData{nr: i, arch: linux.AUDIT_ARCH_X86_64}
		got, err := bpf.Exec(p, data.asInput())
		if err != nil {
			t.Errorf("bpf.Exec() got error: %v, for syscall %d", err, i)
			continue
		}
		want := uint32(linux.SECCOMP_RET_TRAP)
		if _, ok := syscallMap[uintptr(i)]; ok {
			want = linux.SECCOMP_RET_ALLOW
		}
		if got != want {
			t.Errorf("bpf.Exec() = %d, want: %d, for syscall %d", got, want, i)
		}
	}
}

// TestReadDeal checks that a process dies when it trips over the filter and that it
// doesn't die when the filter is not triggered.
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
		} else {
			if err != nil {
				t.Errorf("victim failed to execute, err: %v", err)
				continue
			}
		}
		if !strings.Contains(string(out), test.want) {
			t.Errorf("Victim output is wrong, got: %v, want: %v", err, test.want)
			continue
		}
	}
}
