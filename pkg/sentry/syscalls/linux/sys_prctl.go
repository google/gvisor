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

package linux

import (
	"syscall"

	"gvisor.googlesource.com/gvisor/pkg/abi/linux"
	"gvisor.googlesource.com/gvisor/pkg/bpf"
	"gvisor.googlesource.com/gvisor/pkg/sentry/arch"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs"
	"gvisor.googlesource.com/gvisor/pkg/sentry/kernel"
	"gvisor.googlesource.com/gvisor/pkg/sentry/kernel/auth"
	"gvisor.googlesource.com/gvisor/pkg/sentry/kernel/kdefs"
	"gvisor.googlesource.com/gvisor/pkg/sentry/usermem"
)

// userSockFprog is equivalent to Linux's struct sock_fprog on amd64.
type userSockFprog struct {
	// Len is the length of the filter in BPF instructions.
	Len uint16

	_ [6]byte // padding for alignment

	// Filter is a user pointer to the struct sock_filter array that makes up
	// the filter program. Filter is a uint64 rather than a usermem.Addr
	// because usermem.Addr is actually uintptr, which is not a fixed-size
	// type, and encoding/binary.Read objects to this.
	Filter uint64
}

// Prctl implements linux syscall prctl(2).
// It has a list of subfunctions which operate on the process. The arguments are
// all based on each subfunction.
func Prctl(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	option := args[0].Int()

	switch option {
	case linux.PR_SET_PDEATHSIG:
		sig := linux.Signal(args[1].Int())
		if sig != 0 && !sig.IsValid() {
			return 0, nil, syscall.EINVAL
		}
		t.SetParentDeathSignal(sig)
		return 0, nil, nil

	case linux.PR_GET_PDEATHSIG:
		_, err := t.CopyOut(args[1].Pointer(), int32(t.ParentDeathSignal()))
		return 0, nil, err

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
			return 0, nil, syscall.EINVAL
		}

		return 0, nil, nil

	case linux.PR_SET_NAME:
		addr := args[1].Pointer()
		name, err := t.CopyInString(addr, linux.TASK_COMM_LEN-1)
		if err != nil && err != syscall.ENAMETOOLONG {
			return 0, nil, err
		}
		t.SetName(name)

	case linux.PR_GET_NAME:
		addr := args[1].Pointer()
		buf := make([]byte, linux.TASK_COMM_LEN)
		len := copy(buf, t.Name())
		if len < linux.TASK_COMM_LEN {
			buf[len] = 0
			len++
		}
		_, err := t.CopyOut(addr, buf[:len])
		if err != nil {
			return 0, nil, err
		}

	case linux.PR_SET_MM:
		switch args[1].Int() {
		case linux.PR_SET_MM_EXE_FILE:
			fd := kdefs.FD(args[2].Int())

			file := t.FDMap().GetFile(fd)
			if file == nil {
				return 0, nil, syscall.EBADF
			}
			defer file.DecRef()

			// They trying to set exe to a non-file?
			if !fs.IsFile(file.Dirent.Inode.StableAttr) {
				return 0, nil, syscall.EBADF
			}

			// Set the underlying executable.
			t.MemoryManager().SetExecutable(file.Dirent)
		default:
			return 0, nil, syscall.EINVAL
		}

	case linux.PR_SET_NO_NEW_PRIVS:
		if args[1].Int() != 1 || args[2].Int() != 0 || args[3].Int() != 0 || args[4].Int() != 0 {
			return 0, nil, syscall.EINVAL
		}
		// no_new_privs is assumed to always be set. See
		// auth.Credentials.UpdateForExec.
		return 0, nil, nil

	case linux.PR_GET_NO_NEW_PRIVS:
		if args[1].Int() != 0 || args[2].Int() != 0 || args[3].Int() != 0 || args[4].Int() != 0 {
			return 0, nil, syscall.EINVAL
		}
		return 1, nil, nil

	case linux.PR_SET_SECCOMP:
		if args[1].Int() != linux.SECCOMP_MODE_FILTER {
			// Unsupported mode.
			return 0, nil, syscall.EINVAL
		}
		var fprog userSockFprog
		if _, err := t.CopyIn(args[2].Pointer(), &fprog); err != nil {
			return 0, nil, err
		}
		filter := make([]linux.BPFInstruction, int(fprog.Len))
		if _, err := t.CopyIn(usermem.Addr(fprog.Filter), &filter); err != nil {
			return 0, nil, err
		}
		compiledFilter, err := bpf.Compile(filter)
		if err != nil {
			t.Debugf("Invalid seccomp-bpf filter: %v", err)
			return 0, nil, syscall.EINVAL
		}
		return 0, nil, t.AppendSyscallFilter(compiledFilter)

	case linux.PR_GET_SECCOMP:
		return uintptr(t.SeccompMode()), nil, nil

	case linux.PR_CAPBSET_READ:
		cp := linux.Capability(args[1].Uint64())
		if !cp.Ok() {
			return 0, nil, syscall.EINVAL
		}
		var rv uintptr
		if auth.CapabilitySetOf(cp)&t.Credentials().BoundingCaps != 0 {
			rv = 1
		}
		return rv, nil, nil

	case linux.PR_CAPBSET_DROP:
		cp := linux.Capability(args[1].Uint64())
		if !cp.Ok() {
			return 0, nil, syscall.EINVAL
		}
		return 0, nil, t.DropBoundingCapability(cp)

	default:
		t.Warningf("Unsupported prctl %d", option)
		return 0, nil, syscall.EINVAL
	}

	return 0, nil, nil
}
