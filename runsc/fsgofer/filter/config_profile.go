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

package filter

import (
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/seccomp"
)

var profileFilters = seccomp.SyscallRules{
	unix.SYS_OPENAT: []seccomp.Rule{
		{
			seccomp.MatchAny{},
			seccomp.MatchAny{},
			seccomp.EqualTo(unix.O_RDONLY | unix.O_LARGEFILE | unix.O_CLOEXEC),
		},
	},
	unix.SYS_SETITIMER: {},
	unix.SYS_TIMER_CREATE: []seccomp.Rule{
		{
			seccomp.EqualTo(unix.CLOCK_THREAD_CPUTIME_ID), /* which */
			seccomp.MatchAny{},                            /* sevp */
			seccomp.MatchAny{},                            /* timerid */
		},
	},
	unix.SYS_TIMER_DELETE: []seccomp.Rule{},
	unix.SYS_TIMER_SETTIME: []seccomp.Rule{
		{
			seccomp.MatchAny{}, /* timerid */
			seccomp.EqualTo(0), /* flags */
			seccomp.MatchAny{}, /* new_value */
			seccomp.EqualTo(0), /* old_value */
		},
	},
}
