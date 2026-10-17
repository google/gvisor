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

package boot

import (
	"crypto/sha256"
	"encoding/json"
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/bpf"
	"gvisor.dev/gvisor/pkg/seccomp"
	"gvisor.dev/gvisor/runsc/config"
)

func allowOnlySpec(syscall string) *specs.Spec {
	return &specs.Spec{Linux: &specs.Linux{Seccomp: &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{{
			Names:  []string{syscall},
			Action: specs.ActAllow,
		}},
	}}}
}

func runFilter(t *testing.T, p *bpf.Program, sysno uintptr) uint32 {
	t.Helper()
	d := linux.SeccompData{Nr: int32(sysno), Arch: seccomp.LINUX_AUDIT_ARCH}
	ret, err := bpf.Exec[bpf.NativeEndian](*p, seccomp.DataAsBPFInput(&d, make([]byte, d.SizeBytes())))
	if err != nil {
		t.Fatalf("bpf.Exec: %v", err)
	}
	return ret
}

func TestOCISeccompProgramCache(t *testing.T) {
	conf := &config.Config{OCISeccomp: true}
	const (
		allow = uint32(linux.SECCOMP_RET_ALLOW)
		eperm = uint32(linux.SECCOMP_RET_ERRNO) | uint32(unix.EPERM)
	)

	getpid1, err := buildOCISeccompProgram(conf, allowOnlySpec("getpid"))
	if err != nil {
		t.Fatalf("building getpid profile: %v", err)
	}
	getpid2, err := buildOCISeccompProgram(conf, allowOnlySpec("getpid"))
	if err != nil {
		t.Fatalf("building getpid profile again: %v", err)
	}
	if getpid1 != getpid2 {
		t.Errorf("same profile built twice: got programs %p and %p, want one cached program", getpid1, getpid2)
	}

	getppid, err := buildOCISeccompProgram(conf, allowOnlySpec("getppid"))
	if err != nil {
		t.Fatalf("building getppid profile: %v", err)
	}
	for _, tc := range []struct {
		name  string
		p     *bpf.Program
		sysno uintptr
		want  uint32
	}{
		{"getpid profile, getpid", getpid2, unix.SYS_GETPID, allow},
		{"getpid profile, getppid", getpid2, unix.SYS_GETPPID, eperm},
		{"getppid profile, getpid", getppid, unix.SYS_GETPID, eperm},
		{"getppid profile, getppid", getppid, unix.SYS_GETPPID, allow},
	} {
		if got := runFilter(t, tc.p, tc.sysno); got != tc.want {
			t.Errorf("%s: got %#x, want %#x", tc.name, got, tc.want)
		}
	}
}

func TestOCISeccompProgramCacheSkipsErrors(t *testing.T) {
	conf := &config.Config{OCISeccomp: true}
	bad := allowOnlySpec("getpid")
	bad.Linux.Seccomp.DefaultAction = "SCMP_ACT_BOGUS"
	for i := 0; i < 2; i++ {
		if p, err := buildOCISeccompProgram(conf, bad); err == nil {
			t.Errorf("call %d with invalid profile: got program %p, want error", i, p)
		}
	}
	profile, _ := json.Marshal(bad.Linux.Seccomp)
	if _, ok := ociSeccompCache.programs[sha256.Sum256(profile)]; ok {
		t.Errorf("invalid profile was cached")
	}
}
