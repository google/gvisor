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

// Instrumented builds deliberately permit unrestricted clone calls.
//go:build !race && !msan && !asan

package config

import (
	"testing"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/bpf"
	"gvisor.dev/gvisor/pkg/seccomp"
)

func TestCgoThreadClone(t *testing.T) {
	// musl pthread_create supplies TID and TLS pointers in both supported ABIs.
	const pthreadFlags = unix.CLONE_VM | unix.CLONE_FS | unix.CLONE_FILES |
		unix.CLONE_SIGHAND | unix.CLONE_THREAD | unix.CLONE_SYSVSEM |
		unix.CLONE_SETTLS | unix.CLONE_PARENT_SETTID |
		unix.CLONE_CHILD_CLEARTID | unix.CLONE_DETACHED
	goFlags := uint64(unix.CLONE_VM | unix.CLONE_FS | unix.CLONE_FILES |
		unix.CLONE_SIGHAND | unix.CLONE_THREAD | unix.CLONE_SYSVSEM)
	if seccomp.LINUX_AUDIT_ARCH == linux.AUDIT_ARCH_X86_64 {
		goFlags |= unix.CLONE_SETTLS
	}
	for _, cgo := range []bool{false, true} {
		rules, denyRules := Rules(Options{CgoEnabled: cgo})
		program := seccomp.Program{
			RuleSets: []seccomp.RuleSet{
				{Rules: denyRules},
				{Rules: rules, Action: seccomp.Allow},
			},
			// Interpret the filter without querying the host's seccomp support.
			Options: seccomp.ProgramOptions{DefaultAction: seccomp.KillProcess},
		}
		insns, _, err := program.Build()
		if err != nil {
			t.Fatal(err)
		}
		compiled, err := bpf.Compile(insns, true /* optimize */)
		if err != nil {
			t.Fatal(err)
		}
		for _, tc := range []struct {
			name    string
			args    [6]uint64
			allowed bool
		}{
			{"Go thread", [6]uint64{goFlags, 0x1000}, true},
			{"pthread", [6]uint64{pthreadFlags, 0x1000, 0x2000, 0x3000, 0x4000}, cgo},
			{"process", [6]uint64{pthreadFlags &^ unix.CLONE_THREAD, 0x1000, 0x2000, 0x3000, 0x4000}, false},
			{"namespace", [6]uint64{pthreadFlags | unix.CLONE_NEWUSER, 0x1000, 0x2000, 0x3000, 0x4000}, false},
			{"exit signal", [6]uint64{pthreadFlags | uint64(unix.SIGCHLD), 0x1000, 0x2000, 0x3000, 0x4000}, false},
		} {
			data := linux.SeccompData{Nr: unix.SYS_CLONE, Arch: seccomp.LINUX_AUDIT_ARCH, Args: tc.args}
			got, err := bpf.Exec[bpf.NativeEndian](compiled, seccomp.DataAsBPFInput(&data, make([]byte, data.SizeBytes())))
			if err != nil {
				t.Fatalf("cgo=%t %s: %v", cgo, tc.name, err)
			}
			if allowed := got == uint32(linux.SECCOMP_RET_ALLOW); allowed != tc.allowed {
				t.Errorf("cgo=%t %s: action=%#x, want allowed=%t", cgo, tc.name, got, tc.allowed)
			}
		}
	}
}
