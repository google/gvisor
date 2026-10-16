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

package ptrace

import (
	"os"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/seccomp"
	"gvisor.dev/gvisor/pkg/seccomp/precompiledseccomp"
	"gvisor.dev/gvisor/pkg/sentry/platform"
)

// selfPIDVarName is the seccomp filter variable name used to encode the
// current process ID, which is only known at runtime.
const selfPIDVarName = "ptrace_self_pid"

// ptraceSeccomp implements platform.SeccompInfo.
type ptraceSeccomp struct{}

// Variables implements `platform.SeccompInfo.Variables`.
func (ptraceSeccomp) Variables() precompiledseccomp.Values {
	vars := precompiledseccomp.Values{}
	vars.SetUint64(selfPIDVarName, uint64(os.Getpid()))
	return vars
}

// ConfigKey implements `platform.SeccompInfo.ConfigKey`.
func (ptraceSeccomp) ConfigKey() string {
	return "ptrace"
}

// SyscallFilters implements `platform.SeccompInfo.SyscallFilters`.
func (ptraceSeccomp) SyscallFilters(vars precompiledseccomp.Values) seccomp.SyscallRules {
	return seccomp.MakeSyscallRules(map[uintptr]seccomp.SyscallRule{
		unix.SYS_PTRACE: seccomp.MatchAll{},
		unix.SYS_RT_TGSIGQUEUEINFO: seccomp.PerArg{
			seccomp.EqualTo(vars.GetUint64(selfPIDVarName)),
			seccomp.AnyValue{}, // tid
			seccomp.EqualTo(unix.SIGKILL),
		},
		unix.SYS_TGKILL: seccomp.MatchAll{},
		unix.SYS_WAIT4:  seccomp.MatchAll{},
	})
}

// HottestSyscalls implements `platform.SeccompInfo.HottestSyscalls`.
func (ptraceSeccomp) HottestSyscalls() []uintptr {
	return nil
}

// SeccompInfo returns seccomp information for the ptrace platform.
func (*PTrace) SeccompInfo() platform.SeccompInfo {
	return ptraceSeccomp{}
}

// PrecompiledSeccompInfo implements
// platform.Constructor.PrecompiledSeccompInfo.
func (*constructor) PrecompiledSeccompInfo() []platform.SeccompInfo {
	return []platform.SeccompInfo{(*PTrace)(nil).SeccompInfo()}
}
