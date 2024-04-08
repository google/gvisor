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

//go:build amd64
// +build amd64

package systrap

import (
	"fmt"
	"runtime"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/sentry/arch"
)

func (t *syscallThread) detach() {
	p := t.thread

	// The syscall thread can't handle any signals and doesn't expect to
	// receive anything.
	t.maskAllSignalsAttached()

	regs := p.initRegs
	regs.Rsp = 0
	regs.R12 = uint64(t.stubAddr)
	regs.R13 = uint64(t.sentryMessage.state + 1)
	if t.seccompNotify != nil {
		regs.Rbx = _RUN_SECCOMP_LOOP
	} else {
		regs.Rbx = _RUN_SYSCALL_LOOP
	}
	// Skip the syscall instruction.
	regs.Rip += arch.SyscallWidth
	if err := p.setRegs(&regs); err != nil {
		panic(fmt.Sprintf("ptrace set regs failed: %v", err))
	}
	p.detach()
	if _, _, e := unix.RawSyscall(unix.SYS_TGKILL, uintptr(p.tgid), uintptr(p.tid), uintptr(unix.SIGCONT)); e != 0 {
		panic(fmt.Sprintf("tkill failed: %v", e))
	}
	runtime.UnlockOSThread()

	if t.seccompNotify != nil {
		if err := t.waitForSeccompNotify(); err != nil {
			panic(fmt.Sprintf("%s", err))
		}
	}
}
