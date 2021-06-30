// Copyright 2018 The gVisor Authors.
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
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/fs"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/syserror"
)

// LINT.IfChange

// Lseek implements linux syscall lseek(2).
func Lseek(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	fd := args[0].Int()
	offset := args[1].Int64()
	whence := args[2].Int()

	file := t.GetFile(fd)
	if file == nil {
		return 0, nil, linuxerr.EBADF
	}
	defer file.DecRef(t)

	var sw fs.SeekWhence
	switch whence {
	case 0:
		sw = fs.SeekSet
	case 1:
		sw = fs.SeekCurrent
	case 2:
		sw = fs.SeekEnd
	default:
		return 0, nil, linuxerr.EINVAL
	}

	offset, serr := file.Seek(t, sw, offset)
	err := handleIOError(t, false /* partialResult */, serr, syserror.ERESTARTSYS, "lseek", file)
	if err != nil {
		return 0, nil, err
	}
	return uintptr(offset), nil, err
}

// LINT.ThenChange(vfs2/read_write.go)
