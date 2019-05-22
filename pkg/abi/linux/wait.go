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

package linux

// Options for waitpid(2), wait4(2), and/or waitid(2), from
// include/uapi/linux/wait.h.
const (
	WNOHANG    = 0x00000001
	WUNTRACED  = 0x00000002
	WSTOPPED   = WUNTRACED
	WEXITED    = 0x00000004
	WCONTINUED = 0x00000008
	WNOWAIT    = 0x01000000
	WNOTHREAD  = 0x20000000
	WALL       = 0x40000000
	WCLONE     = 0x80000000
)

// ID types for waitid(2), from include/uapi/linux/wait.h.
const (
	P_ALL  = 0x0
	P_PID  = 0x1
	P_PGID = 0x2
)
