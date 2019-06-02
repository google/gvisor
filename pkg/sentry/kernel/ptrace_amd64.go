// Copyright 2019 The gVisor Authors.
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

// +build amd64

package kernel

import (
	"gvisor.googlesource.com/gvisor/pkg/abi/linux"
	"gvisor.googlesource.com/gvisor/pkg/sentry/usermem"
	"gvisor.googlesource.com/gvisor/pkg/syserror"
)

// ptraceArch implements arch-specific ptrace commands.
func (t *Task) ptraceArch(target *Task, req int64, addr, data usermem.Addr) error {
	switch req {
	case linux.PTRACE_PEEKUSR: // aka PTRACE_PEEKUSER
		n, err := target.Arch().PtracePeekUser(uintptr(addr))
		if err != nil {
			return err
		}
		_, err = t.CopyOut(data, n)
		return err

	case linux.PTRACE_POKEUSR: // aka PTRACE_POKEUSER
		return target.Arch().PtracePokeUser(uintptr(addr), uintptr(data))

	case linux.PTRACE_GETREGS:
		// "Copy the tracee's general-purpose ... registers ... to the address
		// data in the tracer. ... (addr is ignored.) Note that SPARC systems
		// have the meaning of data and addr reversed ..."
		_, err := target.Arch().PtraceGetRegs(&usermem.IOReadWriter{
			Ctx:  t,
			IO:   t.MemoryManager(),
			Addr: data,
			Opts: usermem.IOOpts{
				AddressSpaceActive: true,
			},
		})
		return err

	case linux.PTRACE_GETFPREGS:
		_, err := target.Arch().PtraceGetFPRegs(&usermem.IOReadWriter{
			Ctx:  t,
			IO:   t.MemoryManager(),
			Addr: data,
			Opts: usermem.IOOpts{
				AddressSpaceActive: true,
			},
		})
		return err

	case linux.PTRACE_SETREGS:
		_, err := target.Arch().PtraceSetRegs(&usermem.IOReadWriter{
			Ctx:  t,
			IO:   t.MemoryManager(),
			Addr: data,
			Opts: usermem.IOOpts{
				AddressSpaceActive: true,
			},
		})
		return err

	case linux.PTRACE_SETFPREGS:
		_, err := target.Arch().PtraceSetFPRegs(&usermem.IOReadWriter{
			Ctx:  t,
			IO:   t.MemoryManager(),
			Addr: data,
			Opts: usermem.IOOpts{
				AddressSpaceActive: true,
			},
		})
		return err

	default:
		return syserror.EIO
	}
}
