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

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/bpf"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/seccomp"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/platform/systrap/sysmsg"
)

// sysmsgThread describes a sysmsg stub thread which isn't traced
// and communicates with the Sentry via the sysmsg protocol.
//
// This type of thread is used to execute user processes.
type sysmsgThread struct {
	// subproc is a link to the subprocess which is used to call native
	// system calls.
	subproc *subprocess

	// thread is a thread identifier.
	thread *thread

	// msg is a pointer to a shared sysmsg structure in the Sentry address
	// space which is used to communicate with the thread.
	msg *sysmsg.Msg

	// context is the last context that ran on this thread.
	context *context

	// stackRange is a sysmsg stack in the memory file.
	stackRange memmap.FileRange

	// fpuStateToMsgOffset is the offset of a thread fpu state relative to sysmsg.
	fpuStateToMsgOffset uint64
}

// sysmsgPerThreadMemAddr returns a sysmsg stack address in the thread address
// space.
func (p *sysmsgThread) sysmsgPerThreadMemAddr() uintptr {
	return stubSysmsgStack + sysmsg.PerThreadMemSize*uintptr(p.thread.sysmsgStackID)
}

// mapStack maps a sysmsg stack into the thread address space.
func (p *sysmsgThread) mapStack(addr uintptr, readOnly bool) error {
	prot := uintptr(unix.PROT_READ)
	if !readOnly {
		prot |= unix.PROT_WRITE
	}
	_, err := p.thread.syscallIgnoreInterrupt(&p.thread.initRegs, unix.SYS_MMAP,
		arch.SyscallArgument{Value: addr},
		arch.SyscallArgument{Value: uintptr(p.stackRange.Length())},
		arch.SyscallArgument{Value: prot},
		arch.SyscallArgument{Value: unix.MAP_SHARED | unix.MAP_FILE | unix.MAP_FIXED},
		arch.SyscallArgument{Value: uintptr(p.subproc.memoryFile.FD())},
		arch.SyscallArgument{Value: uintptr(p.stackRange.Start)})
	return err
}

// mapPrivateStack maps a private stack into the thread address space.
func (p *sysmsgThread) mapPrivateStack(addr uintptr, size uintptr) error {
	prot := uintptr(unix.PROT_READ | unix.PROT_WRITE)
	_, err := p.thread.syscallIgnoreInterrupt(&p.thread.initRegs, unix.SYS_MMAP,
		arch.SyscallArgument{Value: addr},
		arch.SyscallArgument{Value: size},
		arch.SyscallArgument{Value: prot},
		arch.SyscallArgument{Value: unix.MAP_PRIVATE | unix.MAP_ANONYMOUS | unix.MAP_FIXED},
		arch.SyscallArgument{Value: 0},
		arch.SyscallArgument{Value: 0})
	return err
}

func (p *sysmsgThread) Debugf(format string, v ...any) {
	if !log.IsLogging(log.Debug) {
		return
	}
	msg := p.msg
	postfix := fmt.Sprintf(": %s", msg)
	p.thread.Debugf(format+postfix, v...)
}

func sysmsgThreadRules(stubStart uintptr) []bpf.Instruction {
	rules := []seccomp.RuleSet{}
	rules = appendSysThreadArchSeccompRules(rules)
	rules = append(rules, []seccomp.RuleSet{
		// Allow instructions from the sysmsg code stub, which is limited by one page.
		{
			Rules: seccomp.SyscallRules{
				unix.SYS_FUTEX: seccomp.Or{
					seccomp.PerArg{
						seccomp.GreaterThan(stubStart),
						seccomp.EqualTo(linux.FUTEX_WAKE),
						seccomp.EqualTo(1),
						seccomp.EqualTo(0),
						seccomp.EqualTo(0),
						seccomp.EqualTo(0),
						seccomp.GreaterThan(stubStart), // rip
					},
					seccomp.PerArg{
						seccomp.GreaterThan(stubStart),
						seccomp.EqualTo(linux.FUTEX_WAIT),
						seccomp.AnyValue{},
						seccomp.EqualTo(0),
						seccomp.EqualTo(0),
						seccomp.EqualTo(0),
						seccomp.GreaterThan(stubStart), // rip
					},
				},
				unix.SYS_RT_SIGRETURN: seccomp.PerArg{
					seccomp.AnyValue{},
					seccomp.AnyValue{},
					seccomp.AnyValue{},
					seccomp.AnyValue{},
					seccomp.AnyValue{},
					seccomp.AnyValue{},
					seccomp.GreaterThan(stubStart), // rip
				},
				unix.SYS_SCHED_YIELD: seccomp.PerArg{
					seccomp.AnyValue{},
					seccomp.AnyValue{},
					seccomp.AnyValue{},
					seccomp.AnyValue{},
					seccomp.AnyValue{},
					seccomp.AnyValue{},
					seccomp.GreaterThan(stubStart), // rip
				},
			},
			Action: linux.SECCOMP_RET_ALLOW,
		},
	}...)
	instrs, err := seccomp.BuildProgram(rules, linux.SECCOMP_RET_TRAP, linux.SECCOMP_RET_TRAP)
	if err != nil {
		panic(fmt.Sprintf("failed to build rules for sysmsg threads: %v", err))
	}

	return instrs
}
