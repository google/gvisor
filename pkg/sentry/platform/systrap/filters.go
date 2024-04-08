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
	"gvisor.dev/gvisor/pkg/seccomp/precompiledseccomp"
	"gvisor.dev/gvisor/pkg/sentry/platform"
)

// sysmsgThreadPriorityVarName is the seccomp filter variable name used to
// encode the sysmsg thread priority.
const sysmsgThreadPriorityVarName = "systrap_sysmsg_thread_priority"

// systrapSeccomp implements platform.SeccompInfo.
type systrapSeccomp struct{}

// Variables implements `platform.SeccompInfo.Variables`.
func (systrapSeccomp) Variables() precompiledseccomp.Values {
	initSysmsgThreadPriority()
	vars := precompiledseccomp.Values{}
	vars.SetUint64(sysmsgThreadPriorityVarName, uint64(sysmsgThreadPriority))
	return vars
}

// ConfigKey implements `platform.SeccompInfo.ConfigKey`.
func (systrapSeccomp) ConfigKey() string {
	return "systrap"
}

// SyscallFilters implements `platform.SeccompInfo.SyscallFilters`.
func (systrapSeccomp) SyscallFilters(vars precompiledseccomp.Values) seccomp.SyscallRules {
	return seccomp.MakeSyscallRules(map[uintptr]seccomp.SyscallRule{
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
		unix.SYS_IOCTL: seccomp.Or{
			seccomp.PerArg{
				seccomp.NonNegativeFD{},
				seccomp.EqualTo(linux.SECCOMP_IOCTL_NOTIF_RECV),
			},
			seccomp.PerArg{
				seccomp.NonNegativeFD{},
				seccomp.EqualTo(linux.SECCOMP_IOCTL_NOTIF_SEND),
			},
			seccomp.PerArg{
				seccomp.NonNegativeFD{},
				seccomp.EqualTo(linux.SECCOMP_IOCTL_NOTIF_SET_FLAGS),
				seccomp.EqualTo(linux.SECCOMP_USER_NOTIF_FD_SYNC_WAKE_UP),
			},
		},
		unix.SYS_WAITID: seccomp.PerArg{
			seccomp.EqualTo(unix.P_PID),
			seccomp.AnyValue{},
			seccomp.AnyValue{},
			seccomp.EqualTo(unix.WEXITED | unix.WNOHANG | unix.WNOWAIT),
		},
		unix.SYS_SETPRIORITY: seccomp.PerArg{
			seccomp.EqualTo(unix.PRIO_PROCESS),
			seccomp.AnyValue{},
			seccomp.EqualTo(vars.GetUint64(sysmsgThreadPriorityVarName)),
		},
	}).Merge(archSyscallFilters())
}

// HottestSyscalls implements `platform.SeccompInfo.HottestSyscalls`.
func (systrapSeccomp) HottestSyscalls() []uintptr {
	return hottestSyscalls()
}

// SeccompInfo returns seccomp filter info for the systrap platform.
func (p *Systrap) SeccompInfo() platform.SeccompInfo {
	return systrapSeccomp{}
}

// PrecompiledSeccompInfo implements
// platform.Constructor.PrecompiledSeccompInfo.
func (*constructor) PrecompiledSeccompInfo() []platform.SeccompInfo {
	return []platform.SeccompInfo{(*Systrap)(nil).SeccompInfo()}
}
