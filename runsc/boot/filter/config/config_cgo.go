// Copyright 2023 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package config

import (
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/seccomp"
)

func cgoFilters() seccomp.SyscallRules {
	return seccomp.MakeSyscallRules(map[uintptr]seccomp.SyscallRule{
		unix.SYS_MMAP: seccomp.Or{
			seccomp.PerArg{
				seccomp.AnyValue{},
				seccomp.AnyValue{},
				seccomp.EqualTo(unix.PROT_NONE),
				seccomp.EqualTo(
					unix.MAP_PRIVATE |
						unix.MAP_ANONYMOUS |
						unix.MAP_NORESERVE),
			},
			seccomp.PerArg{
				seccomp.AnyValue{},
				seccomp.AnyValue{},
				seccomp.AnyValue{},
				seccomp.EqualTo(
					unix.MAP_PRIVATE |
						unix.MAP_ANONYMOUS |
						unix.MAP_STACK),
			},
		},
		unix.SYS_SET_ROBUST_LIST: seccomp.MatchAll{},
		unix.SYS_CLONE3:          seccomp.MatchAll{},
		unix.SYS_RSEQ:            seccomp.MatchAll{},
	})
}
