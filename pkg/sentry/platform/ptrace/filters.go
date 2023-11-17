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
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/seccomp"
	"gvisor.dev/gvisor/pkg/sentry/platform"
)

// SeccompInfo returns seccomp information for the ptrace platform.
func (*PTrace) SeccompInfo() platform.SeccompInfo {
	return platform.StaticSeccompInfo{
		PlatformName: "ptrace",
		Filters: seccomp.MakeSyscallRules(map[uintptr]seccomp.SyscallRule{
			unix.SYS_PTRACE: seccomp.MatchAll{},
			unix.SYS_TGKILL: seccomp.MatchAll{},
			unix.SYS_WAIT4:  seccomp.MatchAll{},
		}),
	}
}

// PrecompiledSeccompInfo implements
// platform.Constructor.PrecompiledSeccompInfo.
func (*constructor) PrecompiledSeccompInfo() []platform.SeccompInfo {
	return []platform.SeccompInfo{(*PTrace)(nil).SeccompInfo()}
}
