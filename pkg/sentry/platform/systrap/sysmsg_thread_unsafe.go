// Copyright 2020 The gVisor Authors.
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
	"fmt"
	"unsafe"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/platform/systrap/sysmsg"
)

func (p *sysmsgThread) unmapStackFromSentry() {
	_, _, errno := unix.RawSyscall(unix.SYS_MUNMAP, sysmsg.MsgToStackAddr(uintptr(unsafe.Pointer(p.msg))), sysmsg.PerThreadSharedStackSize, 0)
	if errno != 0 {
		panic("failed to unmap: " + errno.Error())
	}
}

func (p *sysmsgThread) setMsg(addr uintptr) {
	// add is always from the stub mapping which is mapped once and never
	// moved, so it is safe to use unsafe.Pointer here.
	p.msg = (*sysmsg.Msg)(unsafe.Pointer(addr))
}

func (p *sysmsgThread) init(sentryAddr, guestAddr uintptr) {
	t := p.thread
	// Set the sysmsg signal stack.
	//
	// sentryAddr is from the stub mapping which is mapped once and never
	// moved, so it is safe to use unsafe.Pointer here.
	alt := (*linux.SignalStack)(unsafe.Pointer(sentryAddr))
	*alt = linux.SignalStack{}
	alt.Addr = uint64(guestAddr)
	alt.Size = uint64(sysmsg.MsgOffsetFromSharedStack)
	_, err := t.syscallIgnoreInterrupt(&t.initRegs, unix.SYS_SIGALTSTACK,
		arch.SyscallArgument{Value: guestAddr},
		arch.SyscallArgument{Value: 0},
		arch.SyscallArgument{Value: 0},
		arch.SyscallArgument{Value: 0},
		arch.SyscallArgument{Value: 0},
		arch.SyscallArgument{Value: 0},
	)
	if err != nil {
		panic(fmt.Sprintf("sigaltstack: %v", err))
	}
}

// sysmsgSigactions installs signal handles for signals which can be triggered
// by stubProcess and have to be handled by Sentry.
//
// It is called in a child process after fork(), so the race instrumentation
// has to be disabled.
//
//go:nosplit
//go:norace
func sysmsgSigactions(stubSysmsgStart uintptr) unix.Errno {
	act := linux.SigAction{
		Handler:  uint64(stubSysmsgStart) + uint64(sysmsg.Sighandler_blob_offset____export_sighandler),
		Flags:    linux.SA_ONSTACK | linux.SA_RESTORER | linux.SA_SIGINFO,
		Restorer: uint64(stubSysmsgStart) + uint64(sysmsg.Sighandler_blob_offset____export_restore_rt),
		Mask:     1<<(linux.SIGCHLD-1) | 1<<(linux.SIGSYS-1),
	}

	for _, s := range []unix.Signal{
		unix.SIGSYS,
		unix.SIGBUS,
		unix.SIGFPE,
		unix.SIGILL,
		unix.SIGCHLD,
		unix.SIGTRAP,
		unix.SIGSEGV,
	} {
		_, _, errno := unix.RawSyscall6(unix.SYS_RT_SIGACTION, uintptr(s), uintptr(unsafe.Pointer(&act)), 0, 8, 0, 0)
		if errno != 0 {
			return errno
		}
	}

	return 0
}
