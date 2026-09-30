// Copyright 2026 The gVisor Authors.
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

package api

import (
	"gvisor.dev/gvisor/pkg/log"
)

// LoggingArgs are the arguments to use for changing the logging
// level and strace list.
type LoggingArgs struct {
	// SetLevel is a flag used to indicate that we should update
	// the logging level. We should be able to change the strace
	// list without affecting the logging level and vice versa.
	SetLevel bool

	// Level is the log level that will be set if SetLevel is true.
	Level log.Level

	// SetLogPackets indicates that we should update the log packets flag.
	SetLogPackets bool

	// LogPackets is the actual value to set for LogPackets.
	// SetLogPackets must be enabled to indicate that we're changing
	// the value.
	LogPackets bool

	// SetStrace is a flag used to indicate that strace related
	// arguments were passed in.
	SetStrace bool

	// EnableStrace is a flag from the CLI that specifies whether to
	// enable strace at all. If this flag is false then a completely
	// pristine copy of the syscall table will be swapped in. This
	// approach is used to remain consistent with an empty strace
	// allowlist meaning trace all system calls.
	EnableStrace bool

	// Strace is the allowlist of syscalls to trace to log. If this
	// and StraceEventAllowlist are empty trace all system calls.
	StraceAllowlist []string

	// SetEventStrace is a flag used to indicate that event strace
	// related arguments were passed in.
	SetEventStrace bool

	// StraceEventAllowlist is the allowlist of syscalls to trace
	// to event log.
	StraceEventAllowlist []string
}
