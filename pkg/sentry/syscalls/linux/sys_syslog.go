// Copyright 2018 Google LLC
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
	"gvisor.googlesource.com/gvisor/pkg/sentry/arch"
	"gvisor.googlesource.com/gvisor/pkg/sentry/kernel"
	"gvisor.googlesource.com/gvisor/pkg/syserror"
)

const (
	_SYSLOG_ACTION_READ_ALL    = 3
	_SYSLOG_ACTION_SIZE_BUFFER = 10
)

// logBufLen is the default syslog buffer size on Linux.
const logBufLen = 1 << 17

// Syslog implements part of Linux syscall syslog.
//
// Only the unpriviledged commands are implemented, allowing applications to
// read a fun dmesg.
func Syslog(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	command := args[0].Int()
	buf := args[1].Pointer()
	size := int(args[2].Int())

	switch command {
	case _SYSLOG_ACTION_READ_ALL:
		if size < 0 {
			return 0, nil, syserror.EINVAL
		}
		if size > logBufLen {
			size = logBufLen
		}

		log := t.Kernel().Syslog().Log()
		if len(log) > size {
			log = log[:size]
		}

		n, err := t.CopyOutBytes(buf, log)
		return uintptr(n), nil, err
	case _SYSLOG_ACTION_SIZE_BUFFER:
		return logBufLen, nil, nil
	default:
		return 0, nil, syserror.ENOSYS
	}
}
