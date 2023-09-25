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

package linux

import (
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/bpf"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
)

// userSockFprog is equivalent to Linux's struct sock_fprog on amd64.
//
// +marshal
type userSockFprog struct {
	// Len is the length of the filter in BPF instructions.
	Len uint16

	_ [6]byte // padding for alignment

	// Filter is a user pointer to the struct sock_filter array that makes up
	// the filter program. Filter is a uint64 rather than a hostarch.Addr
	// because hostarch.Addr is actually uintptr, which is not a fixed-size
	// type.
	Filter uint64
}

// seccomp applies a seccomp policy to the current task.
func seccomp(t *kernel.Task, mode, flags uint64, addr hostarch.Addr) error {
	// We only support SECCOMP_SET_MODE_FILTER at the moment.
	if mode != linux.SECCOMP_SET_MODE_FILTER {
		// Unsupported mode.
		return linuxerr.EINVAL
	}

	tsync := flags&linux.SECCOMP_FILTER_FLAG_TSYNC != 0

	// The only flag we support now is SECCOMP_FILTER_FLAG_TSYNC.
	if flags&^linux.SECCOMP_FILTER_FLAG_TSYNC != 0 {
		// Unsupported flag.
		return linuxerr.EINVAL
	}

	var fprog userSockFprog
	if _, err := fprog.CopyIn(t, addr); err != nil {
		return err
	}
	filter := make([]linux.BPFInstruction, int(fprog.Len))
	if _, err := linux.CopyBPFInstructionSliceIn(t, hostarch.Addr(fprog.Filter), filter); err != nil {
		return err
	}
	bpfFilter := make([]bpf.Instruction, len(filter))
	for i, ins := range filter {
		bpfFilter[i] = bpf.Instruction(ins)
	}
	compiledFilter, err := bpf.Compile(bpfFilter)
	if err != nil {
		t.Debugf("Invalid seccomp-bpf filter: %v", err)
		return linuxerr.EINVAL
	}

	return t.AppendSyscallFilter(compiledFilter, tsync)
}

// Seccomp implements linux syscall seccomp(2).
func Seccomp(t *kernel.Task, sysno uintptr, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	return 0, nil, seccomp(t, args[0].Uint64(), args[1].Uint64(), args[2].Pointer())
}
