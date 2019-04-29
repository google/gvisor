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

package proc

import (
	"bytes"
	"fmt"
	"io"

	"gvisor.googlesource.com/gvisor/pkg/abi/linux"
	"gvisor.googlesource.com/gvisor/pkg/sentry/context"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs/fsutil"
	"gvisor.googlesource.com/gvisor/pkg/sentry/kernel"
	"gvisor.googlesource.com/gvisor/pkg/sentry/usermem"
	"gvisor.googlesource.com/gvisor/pkg/syserror"
	"gvisor.googlesource.com/gvisor/pkg/waiter"
)

// execArgType enumerates the types of exec arguments that are exposed through
// proc.
type execArgType int

const (
	cmdlineExecArg execArgType = iota
	environExecArg
)

// execArgInode is a inode containing the exec args (either cmdline or environ)
// for a given task.
//
// +stateify savable
type execArgInode struct {
	fsutil.SimpleFileInode

	// arg is the type of exec argument this file contains.
	arg execArgType

	// t is the Task to read the exec arg line from.
	t *kernel.Task
}

var _ fs.InodeOperations = (*execArgInode)(nil)

// newExecArgFile creates a file containing the exec args of the given type.
func newExecArgInode(t *kernel.Task, msrc *fs.MountSource, arg execArgType) *fs.Inode {
	if arg != cmdlineExecArg && arg != environExecArg {
		panic(fmt.Sprintf("unknown exec arg type %v", arg))
	}
	f := &execArgInode{
		SimpleFileInode: *fsutil.NewSimpleFileInode(t, fs.RootOwner, fs.FilePermsFromMode(0444), linux.PROC_SUPER_MAGIC),
		arg:             arg,
		t:               t,
	}
	return newProcInode(f, msrc, fs.SpecialFile, t)
}

// GetFile implements fs.InodeOperations.GetFile.
func (i *execArgInode) GetFile(ctx context.Context, dirent *fs.Dirent, flags fs.FileFlags) (*fs.File, error) {
	return fs.NewFile(ctx, dirent, flags, &execArgFile{
		arg: i.arg,
		t:   i.t,
	}), nil
}

// +stateify savable
type execArgFile struct {
	waiter.AlwaysReady              `state:"nosave"`
	fsutil.FileGenericSeek          `state:"nosave"`
	fsutil.FileNoIoctl              `state:"nosave"`
	fsutil.FileNoMMap               `state:"nosave"`
	fsutil.FileNotDirReaddir        `state:"nosave"`
	fsutil.FileNoopRelease          `state:"nosave"`
	fsutil.FileNoopFlush            `state:"nosave"`
	fsutil.FileNoopFsync            `state:"nosave"`
	fsutil.FileNoopWrite            `state:"nosave"`
	fsutil.FileUseInodeUnstableAttr `state:"nosave"`

	// arg is the type of exec argument this file contains.
	arg execArgType

	// t is the Task to read the exec arg line from.
	t *kernel.Task
}

var _ fs.FileOperations = (*execArgFile)(nil)

// Read reads the exec arg from the process's address space..
func (f *execArgFile) Read(ctx context.Context, _ *fs.File, dst usermem.IOSequence, offset int64) (int64, error) {
	if offset < 0 {
		return 0, syserror.EINVAL
	}

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
	copyN, err := m.CopyIn(ctx, start, buf, usermem.IOOpts{})
	if copyN == 0 {
		// Nothing to copy.
		return 0, err
	}
	buf = buf[:copyN]

	// On Linux, if the NUL byte at the end of the argument vector has been
	// overwritten, it continues reading the environment vector as part of
	// the argument vector.

	if f.arg == cmdlineExecArg && buf[copyN-1] != 0 {
		// Linux will limit the return up to and including the first null character in argv

		copyN = bytes.IndexByte(buf, 0)
		if copyN == -1 {
			copyN = len(buf)
		}
		// If we found a NUL character in argv, return upto and including that character.
		if copyN < len(buf) {
			buf = buf[:copyN]
		} else { // Otherwise return into envp.
			lengthEnvv := int(m.EnvvEnd() - m.EnvvStart())

			// Upstream limits the returned amount to one page of slop.
			// https://elixir.bootlin.com/linux/v4.20/source/fs/proc/base.c#L208
			// we'll return one page total between argv and envp because of the
			// above page restrictions.
			if lengthEnvv > usermem.PageSize-len(buf) {
				lengthEnvv = usermem.PageSize - len(buf)
			}
			// Make a new buffer to fit the whole thing
			tmp := make([]byte, length+lengthEnvv)
			copyNE, err := m.CopyIn(ctx, m.EnvvStart(), tmp[copyN:], usermem.IOOpts{})
			if err != nil {
				return 0, err
			}

			// Linux will return envp up to and including the first NUL character, so find it.
			for i, c := range tmp[copyN:] {
				if c == 0 {
					copyNE = i
					break
				}
			}

			copy(tmp, buf)
			buf = tmp[:copyN+copyNE]

		}

	}

	n, dstErr := dst.CopyOut(ctx, buf)
	if dstErr != nil {
		return int64(n), dstErr
	}
	return int64(n), err
}
