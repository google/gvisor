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
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/ipc"
	"gvisor.dev/gvisor/pkg/sentry/kernel/shm"
)

// Shmget implements shmget(2).
func Shmget(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	key := ipc.Key(args[0].Int())
	size := uint64(args[1].SizeT())
	flag := args[2].Int()

	private := key == linux.IPC_PRIVATE
	create := flag&linux.IPC_CREAT == linux.IPC_CREAT
	exclusive := flag&linux.IPC_EXCL == linux.IPC_EXCL
	mode := linux.FileMode(flag & 0777)

	pid := int32(t.ThreadGroup().ID())
	r := t.IPCNamespace().ShmRegistry()
	segment, err := r.FindOrCreate(t, pid, key, size, mode, private, create, exclusive)
	if err != nil {
		return 0, nil, err
	}
	defer segment.DecRef(t)
	return uintptr(segment.ID()), nil, nil
}

// findSegment retrives a shm segment by the given id.
//
// findSegment returns a reference on Shm.
func findSegment(t *kernel.Task, id ipc.ID) (*shm.Shm, error) {
	r := t.IPCNamespace().ShmRegistry()
	segment := r.FindByID(id)
	if segment == nil {
		// No segment with provided id.
		return nil, linuxerr.EINVAL
	}
	return segment, nil
}

// Shmat implements shmat(2).
func Shmat(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	id := ipc.ID(args[0].Int())
	addr := args[1].Pointer()
	flag := args[2].Int()

	segment, err := findSegment(t, id)
	if err != nil {
		return 0, nil, linuxerr.EINVAL
	}
	defer segment.DecRef(t)

	opts, err := segment.ConfigureAttach(t, addr, shm.AttachOpts{
		Execute:  flag&linux.SHM_EXEC == linux.SHM_EXEC,
		Readonly: flag&linux.SHM_RDONLY == linux.SHM_RDONLY,
		Remap:    flag&linux.SHM_REMAP == linux.SHM_REMAP,
	})
	if err != nil {
		return 0, nil, err
	}
	addr, err = t.MemoryManager().MMap(t, opts)
	return uintptr(addr), nil, err
}

// Shmdt implements shmdt(2).
func Shmdt(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	addr := args[0].Pointer()
	err := t.MemoryManager().DetachShm(t, addr)
	return 0, nil, err
}

// Shmctl implements shmctl(2).
func Shmctl(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	id := ipc.ID(args[0].Int())
	cmd := args[1].Int()
	buf := args[2].Pointer()

	r := t.IPCNamespace().ShmRegistry()

	switch cmd {
	case linux.SHM_STAT:
		// Technically, we should be treating id as "an index into the kernel's
		// internal array that maintains information about all shared memory
		// segments on the system". Since we don't track segments in an array,
		// we'll just pretend the shmid is the index and do the same thing as
		// IPC_STAT. Linux also uses the index as the shmid.
		fallthrough
	case linux.IPC_STAT:
		segment, err := findSegment(t, id)
		if err != nil {
			return 0, nil, linuxerr.EINVAL
		}
		defer segment.DecRef(t)

		stat, err := segment.IPCStat(t)
		if err == nil {
			_, err = stat.CopyOut(t, buf)
		}
		return 0, nil, err

	case linux.IPC_INFO:
		params := r.IPCInfo()
		_, err := params.CopyOut(t, buf)
		return 0, nil, err

	case linux.SHM_INFO:
		info := r.ShmInfo()
		_, err := info.CopyOut(t, buf)
		return 0, nil, err
	}

	// Remaining commands refer to a specific segment.
	segment, err := findSegment(t, id)
	if err != nil {
		return 0, nil, linuxerr.EINVAL
	}
	defer segment.DecRef(t)

	switch cmd {
	case linux.IPC_SET:
		var ds linux.ShmidDS
		if _, err = ds.CopyIn(t, buf); err != nil {
			return 0, nil, err
		}
		err := segment.Set(t, &ds)
		return 0, nil, err

	case linux.IPC_RMID:
		segment.MarkDestroyed(t)
		return 0, nil, nil

	case linux.SHM_LOCK, linux.SHM_UNLOCK:
		// We currently do not support memory locking anywhere.
		// mlock(2)/munlock(2) are currently stubbed out as no-ops so do the
		// same here.
		t.Kernel().EmitUnimplementedEvent(t)
		return 0, nil, nil

	default:
		return 0, nil, linuxerr.EINVAL
	}
}
