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
	"math"
	"time"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/marshal/primitive"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/fs"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/syserror"
)

const opsMax = 500 // SEMOPM

// Semget handles: semget(key_t key, int nsems, int semflg)
func Semget(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	key := args[0].Int()
	nsems := args[1].Int()
	flag := args[2].Int()

	private := key == linux.IPC_PRIVATE
	create := flag&linux.IPC_CREAT == linux.IPC_CREAT
	exclusive := flag&linux.IPC_EXCL == linux.IPC_EXCL
	mode := linux.FileMode(flag & 0777)

	r := t.IPCNamespace().SemaphoreRegistry()
	set, err := r.FindOrCreate(t, key, nsems, mode, private, create, exclusive)
	if err != nil {
		return 0, nil, err
	}
	return uintptr(set.ID), nil, nil
}

// Semtimedop handles: semop(int semid, struct sembuf *sops, size_t nsops, const struct timespec *timeout)
func Semtimedop(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	// If the timeout argument is NULL, then semtimedop() behaves exactly like semop().
	if args[3].Pointer() == 0 {
		return Semop(t, args)
	}

	id := args[0].Int()
	sembufAddr := args[1].Pointer()
	nsops := args[2].SizeT()
	timespecAddr := args[3].Pointer()
	if nsops <= 0 {
		return 0, nil, linuxerr.EINVAL
	}
	if nsops > opsMax {
		return 0, nil, linuxerr.E2BIG
	}

	ops := make([]linux.Sembuf, nsops)
	if _, err := linux.CopySembufSliceIn(t, sembufAddr, ops); err != nil {
		return 0, nil, err
	}

	var timeout linux.Timespec
	if _, err := timeout.CopyIn(t, timespecAddr); err != nil {
		return 0, nil, err
	}
	if timeout.Sec < 0 || timeout.Nsec < 0 || timeout.Nsec >= 1e9 {
		return 0, nil, linuxerr.EINVAL
	}

	if err := semTimedOp(t, id, ops, true, timeout.ToDuration()); err != nil {
		if linuxerr.Equals(linuxerr.ETIMEDOUT, err) {
			return 0, nil, linuxerr.EAGAIN
		}
		return 0, nil, err
	}
	return 0, nil, nil
}

// Semop handles: semop(int semid, struct sembuf *sops, size_t nsops)
func Semop(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	id := args[0].Int()
	sembufAddr := args[1].Pointer()
	nsops := args[2].SizeT()

	if nsops <= 0 {
		return 0, nil, linuxerr.EINVAL
	}
	if nsops > opsMax {
		return 0, nil, linuxerr.E2BIG
	}

	ops := make([]linux.Sembuf, nsops)
	if _, err := linux.CopySembufSliceIn(t, sembufAddr, ops); err != nil {
		return 0, nil, err
	}
	return 0, nil, semTimedOp(t, id, ops, false, time.Second)
}

func semTimedOp(t *kernel.Task, id int32, ops []linux.Sembuf, haveTimeout bool, timeout time.Duration) error {
	set := t.IPCNamespace().SemaphoreRegistry().FindByID(id)

	if set == nil {
		return linuxerr.EINVAL
	}
	creds := auth.CredentialsFromContext(t)
	pid := t.Kernel().GlobalInit().PIDNamespace().IDOfThreadGroup(t.ThreadGroup())
	for {
		ch, num, err := set.ExecuteOps(t, ops, creds, int32(pid))
		if ch == nil || err != nil {
			return err
		}
		if _, err = t.BlockWithTimeout(ch, haveTimeout, timeout); err != nil {
			set.AbortWait(num, ch)
			return err
		}
	}
}

// Semctl handles: semctl(int semid, int semnum, int cmd, ...)
func Semctl(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	id := args[0].Int()
	num := args[1].Int()
	cmd := args[2].Int()

	switch cmd {
	case linux.SETVAL:
		val := args[3].Int()
		if val > math.MaxInt16 {
			return 0, nil, syserror.ERANGE
		}
		return 0, nil, setVal(t, id, num, int16(val))

	case linux.SETALL:
		array := args[3].Pointer()
		return 0, nil, setValAll(t, id, array)

	case linux.GETVAL:
		v, err := getVal(t, id, num)
		return uintptr(v), nil, err

	case linux.GETALL:
		array := args[3].Pointer()
		return 0, nil, getValAll(t, id, array)

	case linux.IPC_RMID:
		return 0, nil, remove(t, id)

	case linux.IPC_SET:
		arg := args[3].Pointer()
		var s linux.SemidDS
		if _, err := s.CopyIn(t, arg); err != nil {
			return 0, nil, err
		}

		perms := fs.FilePermsFromMode(linux.FileMode(s.SemPerm.Mode & 0777))
		return 0, nil, ipcSet(t, id, auth.UID(s.SemPerm.UID), auth.GID(s.SemPerm.GID), perms)

	case linux.GETPID:
		v, err := getPID(t, id, num)
		return uintptr(v), nil, err

	case linux.IPC_STAT:
		arg := args[3].Pointer()
		ds, err := ipcStat(t, id)
		if err == nil {
			_, err = ds.CopyOut(t, arg)
		}

		return 0, nil, err

	case linux.GETZCNT:
		v, err := getZCnt(t, id, num)
		return uintptr(v), nil, err

	case linux.GETNCNT:
		v, err := getNCnt(t, id, num)
		return uintptr(v), nil, err

	case linux.IPC_INFO:
		buf := args[3].Pointer()
		r := t.IPCNamespace().SemaphoreRegistry()
		info := r.IPCInfo()
		if _, err := info.CopyOut(t, buf); err != nil {
			return 0, nil, err
		}
		return uintptr(r.HighestIndex()), nil, nil

	case linux.SEM_INFO:
		buf := args[3].Pointer()
		r := t.IPCNamespace().SemaphoreRegistry()
		info := r.SemInfo()
		if _, err := info.CopyOut(t, buf); err != nil {
			return 0, nil, err
		}
		return uintptr(r.HighestIndex()), nil, nil

	case linux.SEM_STAT:
		arg := args[3].Pointer()
		// id is an index in SEM_STAT.
		semid, ds, err := semStat(t, id)
		if err != nil {
			return 0, nil, err
		}
		if _, err := ds.CopyOut(t, arg); err != nil {
			return 0, nil, err
		}
		return uintptr(semid), nil, err

	case linux.SEM_STAT_ANY:
		arg := args[3].Pointer()
		// id is an index in SEM_STAT.
		semid, ds, err := semStatAny(t, id)
		if err != nil {
			return 0, nil, err
		}
		if _, err := ds.CopyOut(t, arg); err != nil {
			return 0, nil, err
		}
		return uintptr(semid), nil, err

	default:
		return 0, nil, linuxerr.EINVAL
	}
}

func remove(t *kernel.Task, id int32) error {
	r := t.IPCNamespace().SemaphoreRegistry()
	creds := auth.CredentialsFromContext(t)
	return r.RemoveID(id, creds)
}

func ipcSet(t *kernel.Task, id int32, uid auth.UID, gid auth.GID, perms fs.FilePermissions) error {
	r := t.IPCNamespace().SemaphoreRegistry()
	set := r.FindByID(id)
	if set == nil {
		return linuxerr.EINVAL
	}

	creds := auth.CredentialsFromContext(t)
	kuid := creds.UserNamespace.MapToKUID(uid)
	if !kuid.Ok() {
		return linuxerr.EINVAL
	}
	kgid := creds.UserNamespace.MapToKGID(gid)
	if !kgid.Ok() {
		return linuxerr.EINVAL
	}
	owner := fs.FileOwner{UID: kuid, GID: kgid}
	return set.Change(t, creds, owner, perms)
}

func ipcStat(t *kernel.Task, id int32) (*linux.SemidDS, error) {
	r := t.IPCNamespace().SemaphoreRegistry()
	set := r.FindByID(id)
	if set == nil {
		return nil, linuxerr.EINVAL
	}
	creds := auth.CredentialsFromContext(t)
	return set.GetStat(creds)
}

func semStat(t *kernel.Task, index int32) (int32, *linux.SemidDS, error) {
	r := t.IPCNamespace().SemaphoreRegistry()
	set := r.FindByIndex(index)
	if set == nil {
		return 0, nil, linuxerr.EINVAL
	}
	creds := auth.CredentialsFromContext(t)
	ds, err := set.GetStat(creds)
	if err != nil {
		return 0, ds, err
	}
	return set.ID, ds, nil
}

func semStatAny(t *kernel.Task, index int32) (int32, *linux.SemidDS, error) {
	set := t.IPCNamespace().SemaphoreRegistry().FindByIndex(index)
	if set == nil {
		return 0, nil, linuxerr.EINVAL
	}
	creds := auth.CredentialsFromContext(t)
	ds, err := set.GetStatAny(creds)
	if err != nil {
		return 0, ds, err
	}
	return set.ID, ds, nil
}

func setVal(t *kernel.Task, id int32, num int32, val int16) error {
	r := t.IPCNamespace().SemaphoreRegistry()
	set := r.FindByID(id)
	if set == nil {
		return linuxerr.EINVAL
	}
	creds := auth.CredentialsFromContext(t)
	pid := t.Kernel().GlobalInit().PIDNamespace().IDOfThreadGroup(t.ThreadGroup())
	return set.SetVal(t, num, val, creds, int32(pid))
}

func setValAll(t *kernel.Task, id int32, array hostarch.Addr) error {
	r := t.IPCNamespace().SemaphoreRegistry()
	set := r.FindByID(id)
	if set == nil {
		return linuxerr.EINVAL
	}
	vals := make([]uint16, set.Size())
	if _, err := primitive.CopyUint16SliceIn(t, array, vals); err != nil {
		return err
	}
	creds := auth.CredentialsFromContext(t)
	pid := t.Kernel().GlobalInit().PIDNamespace().IDOfThreadGroup(t.ThreadGroup())
	return set.SetValAll(t, vals, creds, int32(pid))
}

func getVal(t *kernel.Task, id int32, num int32) (int16, error) {
	r := t.IPCNamespace().SemaphoreRegistry()
	set := r.FindByID(id)
	if set == nil {
		return 0, linuxerr.EINVAL
	}
	creds := auth.CredentialsFromContext(t)
	return set.GetVal(num, creds)
}

func getValAll(t *kernel.Task, id int32, array hostarch.Addr) error {
	r := t.IPCNamespace().SemaphoreRegistry()
	set := r.FindByID(id)
	if set == nil {
		return linuxerr.EINVAL
	}
	creds := auth.CredentialsFromContext(t)
	vals, err := set.GetValAll(creds)
	if err != nil {
		return err
	}
	_, err = primitive.CopyUint16SliceOut(t, array, vals)
	return err
}

func getPID(t *kernel.Task, id int32, num int32) (int32, error) {
	r := t.IPCNamespace().SemaphoreRegistry()
	set := r.FindByID(id)
	if set == nil {
		return 0, linuxerr.EINVAL
	}
	creds := auth.CredentialsFromContext(t)
	gpid, err := set.GetPID(num, creds)
	if err != nil {
		return 0, err
	}
	// Convert pid from init namespace to the caller's namespace.
	tg := t.PIDNamespace().ThreadGroupWithID(kernel.ThreadID(gpid))
	if tg == nil {
		return 0, nil
	}
	return int32(tg.ID()), nil
}

func getZCnt(t *kernel.Task, id int32, num int32) (uint16, error) {
	r := t.IPCNamespace().SemaphoreRegistry()
	set := r.FindByID(id)
	if set == nil {
		return 0, linuxerr.EINVAL
	}
	creds := auth.CredentialsFromContext(t)
	return set.CountZeroWaiters(num, creds)
}

func getNCnt(t *kernel.Task, id int32, num int32) (uint16, error) {
	r := t.IPCNamespace().SemaphoreRegistry()
	set := r.FindByID(id)
	if set == nil {
		return 0, linuxerr.EINVAL
	}
	creds := auth.CredentialsFromContext(t)
	return set.CountNegativeWaiters(num, creds)
}
