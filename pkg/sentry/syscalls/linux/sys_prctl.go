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
	"fmt"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/marshal/primitive"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/fs"
	"gvisor.dev/gvisor/pkg/sentry/fsbridge"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/mm"
	"gvisor.dev/gvisor/pkg/syserror"
)

// Prctl implements linux syscall prctl(2).
// It has a list of subfunctions which operate on the process. The arguments are
// all based on each subfunction.
func Prctl(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	option := args[0].Int()

	switch option {
	case linux.PR_SET_PDEATHSIG:
		sig := linux.Signal(args[1].Int())
		if sig != 0 && !sig.IsValid() {
			return 0, nil, syserror.EINVAL
		}
		t.SetParentDeathSignal(sig)
		return 0, nil, nil

	case linux.PR_GET_PDEATHSIG:
		_, err := primitive.CopyInt32Out(t, args[1].Pointer(), int32(t.ParentDeathSignal()))
		return 0, nil, err

	case linux.PR_GET_DUMPABLE:
		d := t.MemoryManager().Dumpability()
		switch d {
		case mm.NotDumpable:
			return linux.SUID_DUMP_DISABLE, nil, nil
		case mm.UserDumpable:
			return linux.SUID_DUMP_USER, nil, nil
		case mm.RootDumpable:
			return linux.SUID_DUMP_ROOT, nil, nil
		default:
			panic(fmt.Sprintf("Unknown dumpability %v", d))
		}

	case linux.PR_SET_DUMPABLE:
		var d mm.Dumpability
		switch args[1].Int() {
		case linux.SUID_DUMP_DISABLE:
			d = mm.NotDumpable
		case linux.SUID_DUMP_USER:
			d = mm.UserDumpable
		default:
			// N.B. Userspace may not pass SUID_DUMP_ROOT.
			return 0, nil, syserror.EINVAL
		}
		t.MemoryManager().SetDumpability(d)
		return 0, nil, nil

	case linux.PR_GET_KEEPCAPS:
		if t.Credentials().KeepCaps {
			return 1, nil, nil
		}

		return 0, nil, nil

	case linux.PR_SET_KEEPCAPS:
		val := args[1].Int()
		// prctl(2): arg2 must be either 0 (permitted capabilities are cleared)
		// or 1 (permitted capabilities are kept).
		if val == 0 {
			t.SetKeepCaps(false)
		} else if val == 1 {
			t.SetKeepCaps(true)
		} else {
			return 0, nil, syserror.EINVAL
		}

		return 0, nil, nil

	case linux.PR_SET_NAME:
		addr := args[1].Pointer()
		name, err := t.CopyInString(addr, linux.TASK_COMM_LEN-1)
		if err != nil && !linuxerr.Equals(linuxerr.ENAMETOOLONG, err) {
			return 0, nil, err
		}
		t.SetName(name)

	case linux.PR_GET_NAME:
		addr := args[1].Pointer()
		buf := t.CopyScratchBuffer(linux.TASK_COMM_LEN)
		len := copy(buf, t.Name())
		if len < linux.TASK_COMM_LEN {
			buf[len] = 0
			len++
		}
		_, err := t.CopyOutBytes(addr, buf[:len])
		if err != nil {
			return 0, nil, err
		}

	case linux.PR_SET_MM:
		if !t.HasCapability(linux.CAP_SYS_RESOURCE) {
			return 0, nil, syserror.EPERM
		}

		switch args[1].Int() {
		case linux.PR_SET_MM_EXE_FILE:
			fd := args[2].Int()

			file := t.GetFile(fd)
			if file == nil {
				return 0, nil, syserror.EBADF
			}
			defer file.DecRef(t)

			// They trying to set exe to a non-file?
			if !fs.IsFile(file.Dirent.Inode.StableAttr) {
				return 0, nil, syserror.EBADF
			}

			// Set the underlying executable.
			t.MemoryManager().SetExecutable(t, fsbridge.NewFSFile(file))

		case linux.PR_SET_MM_AUXV,
			linux.PR_SET_MM_START_CODE,
			linux.PR_SET_MM_END_CODE,
			linux.PR_SET_MM_START_DATA,
			linux.PR_SET_MM_END_DATA,
			linux.PR_SET_MM_START_STACK,
			linux.PR_SET_MM_START_BRK,
			linux.PR_SET_MM_BRK,
			linux.PR_SET_MM_ARG_START,
			linux.PR_SET_MM_ARG_END,
			linux.PR_SET_MM_ENV_START,
			linux.PR_SET_MM_ENV_END:

			t.Kernel().EmitUnimplementedEvent(t)
			fallthrough
		default:
			return 0, nil, syserror.EINVAL
		}

	case linux.PR_SET_NO_NEW_PRIVS:
		if args[1].Int() != 1 || args[2].Int() != 0 || args[3].Int() != 0 || args[4].Int() != 0 {
			return 0, nil, syserror.EINVAL
		}
		// PR_SET_NO_NEW_PRIVS is assumed to always be set.
		// See kernel.Task.updateCredsForExecLocked.
		return 0, nil, nil

	case linux.PR_GET_NO_NEW_PRIVS:
		if args[1].Int() != 0 || args[2].Int() != 0 || args[3].Int() != 0 || args[4].Int() != 0 {
			return 0, nil, syserror.EINVAL
		}
		return 1, nil, nil

	case linux.PR_SET_PTRACER:
		pid := args[1].Int()
		switch pid {
		case 0:
			t.ClearYAMAException()
			return 0, nil, nil
		case linux.PR_SET_PTRACER_ANY:
			t.SetYAMAException(nil)
			return 0, nil, nil
		default:
			tracer := t.PIDNamespace().TaskWithID(kernel.ThreadID(pid))
			if tracer == nil {
				return 0, nil, syserror.EINVAL
			}
			t.SetYAMAException(tracer)
			return 0, nil, nil
		}

	case linux.PR_SET_SECCOMP:
		if args[1].Int() != linux.SECCOMP_MODE_FILTER {
			// Unsupported mode.
			return 0, nil, syserror.EINVAL
		}

		return 0, nil, seccomp(t, linux.SECCOMP_SET_MODE_FILTER, 0, args[2].Pointer())

	case linux.PR_GET_SECCOMP:
		return uintptr(t.SeccompMode()), nil, nil

	case linux.PR_CAPBSET_READ:
		cp := linux.Capability(args[1].Uint64())
		if !cp.Ok() {
			return 0, nil, syserror.EINVAL
		}
		var rv uintptr
		if auth.CapabilitySetOf(cp)&t.Credentials().BoundingCaps != 0 {
			rv = 1
		}
		return rv, nil, nil

	case linux.PR_CAPBSET_DROP:
		cp := linux.Capability(args[1].Uint64())
		if !cp.Ok() {
			return 0, nil, syserror.EINVAL
		}
		return 0, nil, t.DropBoundingCapability(cp)

	case linux.PR_GET_TIMING,
		linux.PR_SET_TIMING,
		linux.PR_GET_TSC,
		linux.PR_SET_TSC,
		linux.PR_TASK_PERF_EVENTS_DISABLE,
		linux.PR_TASK_PERF_EVENTS_ENABLE,
		linux.PR_GET_TIMERSLACK,
		linux.PR_SET_TIMERSLACK,
		linux.PR_MCE_KILL,
		linux.PR_MCE_KILL_GET,
		linux.PR_GET_TID_ADDRESS,
		linux.PR_SET_CHILD_SUBREAPER,
		linux.PR_GET_CHILD_SUBREAPER,
		linux.PR_GET_THP_DISABLE,
		linux.PR_SET_THP_DISABLE,
		linux.PR_MPX_ENABLE_MANAGEMENT,
		linux.PR_MPX_DISABLE_MANAGEMENT:

		t.Kernel().EmitUnimplementedEvent(t)
		fallthrough
	default:
		return 0, nil, syserror.EINVAL
	}

	return 0, nil, nil
}
