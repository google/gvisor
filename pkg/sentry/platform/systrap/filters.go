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

package systrap

import (
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/seccomp"
)

// SyscallFilters returns syscalls made exclusively by the systrap platform.
func (p *Systrap) SyscallFilters() seccomp.SyscallRules {
	r := seccomp.SyscallRules{
		unix.SYS_PTRACE: seccomp.Or{
			seccomp.PerArg{
				seccomp.EqualTo(unix.PTRACE_ATTACH),
			},
			seccomp.PerArg{
				seccomp.EqualTo(unix.PTRACE_CONT),
				seccomp.AnyValue{},
				seccomp.EqualTo(0),
				seccomp.EqualTo(0),
			},
			seccomp.PerArg{
				seccomp.EqualTo(unix.PTRACE_GETEVENTMSG),
			},
			seccomp.PerArg{
				seccomp.EqualTo(unix.PTRACE_GETREGSET),
				seccomp.AnyValue{},
				seccomp.EqualTo(linux.NT_PRSTATUS),
			},
			seccomp.PerArg{
				seccomp.EqualTo(unix.PTRACE_GETSIGINFO),
			},
			seccomp.PerArg{
				seccomp.EqualTo(unix.PTRACE_SETOPTIONS),
				seccomp.AnyValue{},
				seccomp.EqualTo(0),
				seccomp.EqualTo(unix.PTRACE_O_TRACESYSGOOD | unix.PTRACE_O_TRACEEXIT | unix.PTRACE_O_EXITKILL),
			},
			seccomp.PerArg{
				seccomp.EqualTo(unix.PTRACE_SETREGSET),
				seccomp.AnyValue{},
				seccomp.EqualTo(linux.NT_PRSTATUS),
			},
			seccomp.PerArg{
				seccomp.EqualTo(linux.PTRACE_SETSIGMASK),
				seccomp.AnyValue{},
				seccomp.EqualTo(8),
			},
			seccomp.PerArg{
				seccomp.EqualTo(unix.PTRACE_SYSEMU),
				seccomp.AnyValue{},
				seccomp.EqualTo(0),
				seccomp.EqualTo(0),
			},
			seccomp.PerArg{
				seccomp.EqualTo(unix.PTRACE_DETACH),
			},
		},
		unix.SYS_TGKILL: seccomp.MatchAll{},
		unix.SYS_WAIT4:  seccomp.MatchAll{},
		unix.SYS_SETPRIORITY: seccomp.PerArg{
			seccomp.EqualTo(unix.PRIO_PROCESS),
			seccomp.AnyValue{},
			seccomp.EqualTo(sysmsgThreadPriority),
		},
	}
	r.Merge(p.archSyscallFilters())
	return r
}
