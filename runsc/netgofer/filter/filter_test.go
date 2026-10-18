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

package filter

import (
	"testing"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/seccomp"
)

func TestRules(t *testing.T) {
	rules := Rules(Options{})

	// Check some allowed syscalls
	allowed := []uintptr{
		unix.SYS_READ,
		unix.SYS_WRITE,
		unix.SYS_RECVMMSG,
		unix.SYS_SENDMMSG,
		unix.SYS_CONNECT,
		unix.SYS_EPOLL_CTL,
		unix.SYS_MMAP,
		unix.SYS_PREAD64,
		unix.SYS_TGKILL,
	}
	for _, sys := range allowed {
		if !rules.Has(sys) {
			t.Errorf("Rules().Has(%d) = false, want true", sys)
		}
	}

	// Check some denied syscalls
	denied := []uintptr{
		unix.SYS_OPENAT,
		unix.SYS_EXECVE,
		unix.SYS_BIND,
		unix.SYS_LISTEN,
		unix.SYS_ACCEPT,
		unix.SYS_RECVMSG,
		unix.SYS_SENDMSG,
		unix.SYS_PTRACE,
		unix.SYS_MOUNT,
	}
	for _, sys := range denied {
		if rules.Has(sys) {
			t.Errorf("Rules().Has(%d) = true, want false", sys)
		}
	}
}

func TestRulesExtraRules(t *testing.T) {
	const extraSyscall = uintptr(123456)
	rules := Rules(Options{
		ExtraRules: []seccomp.SyscallRules{
			seccomp.NewSyscallRules().Add(extraSyscall, seccomp.MatchAll{}),
		},
	})
	if !rules.Has(extraSyscall) {
		t.Fatalf("Rules().Has(%d) = false, want true", extraSyscall)
	}
}
