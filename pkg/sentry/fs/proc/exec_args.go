// Copyright 2018 Google Inc.
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

package proc

import (
	"fmt"
	"io"

	"gvisor.googlesource.com/gvisor/pkg/sentry/context"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs/ramfs"
	"gvisor.googlesource.com/gvisor/pkg/sentry/kernel"
	"gvisor.googlesource.com/gvisor/pkg/sentry/usermem"
	"gvisor.googlesource.com/gvisor/pkg/syserror"
)

// execArgType enumerates the types of exec arguments that are exposed through
// proc.
type execArgType int

const (
	cmdlineExecArg execArgType = iota
	environExecArg
)

// execArgFile is a file containing the exec args (either cmdline or environ)
// for a given task.
type execArgFile struct {
	ramfs.Entry

	// arg is the type of exec argument this file contains.
	arg execArgType

	// t is the Task to read the exec arg line from.
	t *kernel.Task
}

// newExecArgFile creates a file containing the exec args of the given type.
func newExecArgFile(t *kernel.Task, msrc *fs.MountSource, arg execArgType) *fs.Inode {
	if arg != cmdlineExecArg && arg != environExecArg {
		panic(fmt.Sprintf("unknown exec arg type %v", arg))
	}
	f := &execArgFile{
		arg: arg,
		t:   t,
	}
	f.InitEntry(t, fs.RootOwner, fs.FilePermsFromMode(0444))
	return newFile(f, msrc, fs.SpecialFile, t)
}

// DeprecatedPreadv reads the exec arg from the process's address space..
func (f *execArgFile) DeprecatedPreadv(ctx context.Context, dst usermem.IOSequence, offset int64) (int64, error) {
	if offset < 0 {
		return 0, syserror.EINVAL
	}

	// N.B. Linux 4.2 eliminates the arbitrary one page limit.
	if offset > usermem.PageSize {
		return 0, io.EOF
	}
	dst = dst.TakeFirst64(usermem.PageSize - offset)

	m, err := getTaskMM(f.t)
	if err != nil {
		return 0, err
	}
	defer m.DecUsers(ctx)

	// Figure out the bounds of the exec arg we are trying to read.
	var execArgStart, execArgEnd usermem.Addr
	switch f.arg {
	case cmdlineExecArg:
		execArgStart, execArgEnd = m.ArgvStart(), m.ArgvEnd()
	case environExecArg:
		execArgStart, execArgEnd = m.EnvvStart(), m.EnvvEnd()
	default:
		panic(fmt.Sprintf("unknown exec arg type %v", f.arg))
	}
	if execArgStart == 0 || execArgEnd == 0 {
		// Don't attempt to read before the start/end are set up.
		return 0, io.EOF
	}

	start, ok := execArgStart.AddLength(uint64(offset))
	if !ok {
		return 0, io.EOF
	}
	if start >= execArgEnd {
		return 0, io.EOF
	}

	length := int(execArgEnd - start)
	if dstlen := dst.NumBytes(); int64(length) > dstlen {
		length = int(dstlen)
	}

	buf := make([]byte, length)
	// N.B. Technically this should be usermem.IOOpts.IgnorePermissions = true
	// until Linux 4.9 (272ddc8b3735 "proc: don't use FOLL_FORCE for reading
	// cmdline and environment").
	copyN, copyErr := m.CopyIn(ctx, start, buf, usermem.IOOpts{})
	if copyN == 0 {
		// Nothing to copy.
		return 0, copyErr
	}
	buf = buf[:copyN]

	// TODO: On Linux, if the NUL byte at the end of the
	// argument vector has been overwritten, it continues reading the
	// environment vector as part of the argument vector.

	n, dstErr := dst.CopyOut(ctx, buf)
	if dstErr != nil {
		return int64(n), dstErr
	}
	return int64(n), copyErr
}
