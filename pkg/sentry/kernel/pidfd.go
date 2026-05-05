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

package kernel

import (
	"sync/atomic"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/atomicbitops"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/kernfs"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/waiter"
)

// pidFD implements vfs.FileDescriptionImpl for pidfds.
//
// +stateify savable
type pidFD struct {
	vfsFD vfs.FileDescription
	vfs.FileDescriptionDefaultImpl
	vfs.DentryMetadataFileDescriptionImpl
	vfs.NoLockFD

	// isThread is true if the pidfd represents a task.
	// It is set during creation and is immutable thereafter.
	isThread bool

	// All pidfds pointing to the same task point to the one pid struct.
	// It is set during creation and is immutable thereafter.
	pid *pid
}

// Release implements vfs.FileDescriptionImpl.Release.
func (f *pidFD) Release(ctx context.Context) {
}

// Readiness implements waiter.Waitable.Readiness.
func (f *pidFD) Readiness(mask waiter.EventMask) waiter.EventMask {
	// man pidfd_open(2) says:
	//	   When the task that it refers to terminates and becomes a
	//	   zombie, these interfaces indicate the file descriptor as
	//	   readable (EPOLLIN).  When the task is reaped, these interfaces
	//	   produce a hangup event (EPOLLHUP).
	//     ...
	//	   •  With PIDFD_THREAD, the file descriptor becomes readable when
	//		  the task exits and becomes a zombie, even if the thread-
	//		  group is not empty.
	//	   •  Without PIDFD_THREAD, the file descriptor becomes readable
	//		  only when the last thread in the thread group exits.
	if f.pid.t.Load() == nil {
		return waiter.EventHUp | waiter.ReadableEvents
	}
	if f.pid.ready.Load() {
		return waiter.ReadableEvents
	}
	return 0
}

// EventRegister implements waiter.Waitable.EventRegister.
func (f *pidFD) EventRegister(e *waiter.Entry) error {
	f.pid.notifier.EventRegister(e)
	return nil
}

// EventUnregister implements waiter.Waitable.EventUnregister.
func (f *pidFD) EventUnregister(e *waiter.Entry) {
	f.pid.notifier.EventUnregister(e)
}

// Epollable implements vfs.FileDescriptionImpl.Epollable.
func (f *pidFD) Epollable() bool {
	return true
}

// RegisterFileAsyncHandler implements vfs.FileDescriptionImpl.RegisterFileAsyncHandler.
func (f *pidFD) RegisterFileAsyncHandler(fd *vfs.FileDescription) error {
	return linuxerr.ENOTTY
}

// UnregisterFileAsyncHandler implements vfs.FileDescriptionImpl.UnregisterFileAsyncHandler.
func (f *pidFD) UnregisterFileAsyncHandler(fd *vfs.FileDescription) {}

// PIDFDOpen helps implement the linux syscall pidfd_open(2).
// It returns an fd with an extra reference.
func (t *Task) PIDFDOpen(tid ThreadID, isThread bool, nonBlock bool) (*vfs.FileDescription, error) {
	t.tg.pidns.owner.mu.Lock()
	pid, err := t.pidStructFromTIDLocked(tid, isThread)
	t.tg.pidns.owner.mu.Unlock()
	if err != nil {
		return nil, err
	}
	f := &pidFD{
		isThread: isThread,
		pid:      pid,
	}

	vd := t.Kernel().VFS().NewAnonVirtualDentry("[pidfd]")
	defer vd.DecRef(t)
	var flags uint32
	if nonBlock {
		flags |= linux.O_NONBLOCK
	}
	err = f.vfsFD.Init(f, flags, t.Credentials(), vd.Mount(), vd.Dentry(), &vfs.FileDescriptionOptions{
		UseDentryMetadata: true,
	})
	if err != nil {
		return nil, err
	}
	return &f.vfsFD, nil
}

// PIDFDGetFD helps implement the Linux syscall pidfd_getfd(2).
func (t *Task) PIDFDGetFD(pidfd int32, targetfd int32, flags uint32) (uintptr, error) {
	file := t.GetFile(pidfd)
	if file == nil {
		return 0, linuxerr.EBADF
	}
	defer file.DecRef(t)
	pfd, ok := file.Impl().(*pidFD)
	if !ok {
		return 0, linuxerr.EBADF
	}

	target, err := pfd.liveTask()
	if err != nil {
		return 0, err
	}
	if !t.CanTrace(target, true) {
		return 0, linuxerr.EPERM
	}

	targetFile := target.GetFile(targetfd)
	if targetFile == nil {
		return 0, linuxerr.EBADF
	}
	defer targetFile.DecRef(t)

	// man pidfd_getfd(2) says:
	//  "The close-on-exec flag (FD_CLOEXEC; see fcntl(2)) is set on the
	//	 file descriptor returned by pidfd_getfd()."
	fd, err := t.NewFDFrom(0, targetFile, FDFlags{
		CloseOnExec: true,
	})
	if err != nil {
		return 0, err
	}
	return uintptr(fd), nil
}

func (f *pidFD) liveTask() (*Task, error) {
	if f.pid.ready.Load() {
		return nil, linuxerr.ESRCH
	}
	t := f.pid.t.Load()
	if t == nil {
		return nil, linuxerr.ESRCH
	}
	// Not necessary on account of the "ready" check above, but extra defense feels good.
	if t.ExitState() >= TaskExitZombie {
		return nil, linuxerr.ESRCH
	}
	return t, nil
}

// ThreadGroupFromPIDFD returns the thread group associated with the integral pidfd
// and a bool indicating if the pidfd has O_NONBLOCK set.
// Note: Returns EINVAL if the pidfd is a PIDFD_THREAD pidfd.
func (t *Task) ThreadGroupFromPIDFD(pfdNum int32) (*ThreadGroup, bool, error) {
	pfd, err := t.pidFDFromFDNum(pfdNum)
	if err != nil {
		return nil, false, err
	}
	if pfd.isThread {
		return nil, false, linuxerr.EINVAL
	}

	target := pfd.pid.t.Load()
	if target == nil {
		return nil, false, linuxerr.ESRCH
	}
	tg := target.ThreadGroup()

	nonBlock := pfd.vfsFD.StatusFlags()&linux.O_NONBLOCK != 0
	return tg, nonBlock, nil
}

func (t *Task) pidFDFromFDNum(pfdNum int32) (*pidFD, error) {
	file := t.GetFile(pfdNum)
	if file == nil {
		return nil, linuxerr.EBADF
	}
	defer file.DecRef(t)
	pfd, ok := file.Impl().(*pidFD)
	if !ok {
		return nil, linuxerr.EBADF
	}
	return pfd, nil
}

// pid represents a task for the purposes of pidfds.
// There is at most one pid struct per task which all pidfds refer to.
//
// +stateify savable
type pid struct {
	// The task that this pid struct refers to.
	// It is set during creation and is not mutated until it's nilled when the task is reaped.
	t atomic.Pointer[Task] `state:".(*Task)"`

	// For a non-leader subthread, a set ready means that it has become a zombie.
	// For a leader thread, a set ready means that it has become a zombie and that the
	// thread group has no other tasks.
	ready atomicbitops.Bool

	notifier waiter.Queue
}

func (t *Task) pidStructFromTIDLocked(tid ThreadID, isThread bool) (*pid, error) {
	t2 := t.tg.pidns.tasks[tid]
	if t2 == nil {
		return nil, linuxerr.ESRCH
	}
	isLeader := t2 == t2.tg.leader
	if !isThread && !isLeader {
		return nil, linuxerr.ENOENT
	}
	return t2.pidStructLocked()
}

func (t *Task) pidStructLocked() (*pid, error) {
	if t.ExitState() == TaskExitDead {
		return nil, linuxerr.ESRCH
	}
	if t.pid != nil {
		return t.pid, nil
	}
	t.pid = &pid{}
	t.pid.t.Store(t)

	isLeader := t == t.tg.leader
	isZombie := t.exitStateLocked() == TaskExitZombie
	if isLeader {
		if isZombie && t.tg.tasksCount == 1 {
			t.pid.ready.Store(true)
		}
	} else if isZombie {
		t.pid.ready.Store(true)
	}

	return t.pid, nil
}

// notifyPIDFDsOnDeathLocked() is invoked by Task.exitNotifyLocked() when a task is dying.
// Preconditions: The TaskSet mutex must be held.
func (t *Task) notifyPIDFDsOnDeathLocked() {
	if pid := t.pid; pid != nil {
		// Stop referring to t from the pid struct, so that the presence of pidfds does not
		// prevent the GC from reclaiming (the sizeable) Task t.
		if pid.t.Swap(nil) == nil {
			return
		}
		pid.notifier.Notify(waiter.ReadableEvents | waiter.EventHUp)
		t.pid = nil // Inconsequential but hygienic.
	}
}

// notifyPIDFDsLocked() is invoked by runExitNotify.execute() in the following cases:
// - If t is a non leader, as soon as it becomes a zombie.
// - If t is a leader, when it becomes a zombie and it is the last task in the thread group.
// Preconditions: The TaskSet mutex must be held.
func (t *Task) notifyPIDFDsLocked() {
	if pid := t.pid; pid != nil {
		if pid.ready.Swap(true) {
			return
		}
		pid.notifier.Notify(waiter.ReadableEvents)
	}
}

// TaskOwnedInode is an interface for /proc/$pid inodes so that pidfd syscalls can
// also work on "classic" pidfds from procfs.
type TaskOwnedInode interface {
	TaskFromProcPIDInode() *Task
}

// pidfd syscalls work on not just pidfds, but also /proc/$pid procfs fds.
// Man pidfd_send_signal(2) says:
//
//	 "The pidfd argument is a PID file descriptor, a file descriptor
//	 that refers to process.  Such a file descriptor can be obtained in
//	 any of the following ways:
//		   - by opening a /proc/pid directory;
//		   - using pidfd_open(2); or
//		   - via the PID file descriptor that is returned by a call to
//			   clone(2) or clone3(2) that specifies the CLONE_PIDFD flag."
//
// taskFromProcPIDFD returns the task associated with the /proc/$pid node represented by vfsfd.
// Returns an error if the fd is not a /proc/$pid node.
func taskFromProcPIDFD(vfsfd *vfs.FileDescription) (*Task, error) {
	d, ok := vfsfd.Dentry().Impl().(*kernfs.Dentry)
	if !ok {
		return nil, linuxerr.EBADF
	}
	i, ok := d.Inode().(TaskOwnedInode)
	if !ok {
		return nil, linuxerr.EBADF
	}
	t := i.TaskFromProcPIDInode()
	if t == nil {
		return nil, linuxerr.ESRCH
	}
	return t, nil
}

// PIDFDSendSignal sends a signal to the task or thread group associated with the pidfd represented
// by vfsfd. It could either be a true pidfd or a /proc/pid node.
func (t *Task) PIDFDSendSignal(vfsfd *vfs.FileDescription, sig linux.Signal, info *linux.SignalInfo, flags uint32) error {
	pfd, isPidFD := vfsfd.Impl().(*pidFD)
	var target *Task
	var err error

	if isPidFD {
		target = pfd.pid.t.Load()
		if target == nil {
			err = linuxerr.ESRCH
		}
	} else {
		target, err = taskFromProcPIDFD(vfsfd)
	}
	if err != nil {
		return err
	}

	effectiveFlags := flags
	if isPidFD && effectiveFlags == 0 {
		if pfd.isThread {
			effectiveFlags = linux.PIDFD_SIGNAL_THREAD
		} else {
			effectiveFlags = linux.PIDFD_SIGNAL_THREAD_GROUP
		}
	}
	if effectiveFlags == 0 {
		effectiveFlags = linux.PIDFD_SIGNAL_THREAD_GROUP
	}

	if info == nil {
		info = &linux.SignalInfo{
			Signo: int32(sig),
			Code:  linux.SI_USER,
		}
		info.SetPID(int32(target.PIDNamespace().IDOfTask(t)))
		info.SetUID(int32(t.Credentials().RealKUID.In(target.UserNamespace()).OrOverflow()))
	} else {
		if info.Signo != int32(sig) {
			return linuxerr.EINVAL
		}
		// Do not allow spoofing unless to self.
		if info.Code >= 0 || info.Code == linux.SI_TKILL {
			if target != t || effectiveFlags == linux.PIDFD_SIGNAL_PROCESS_GROUP {
				return linuxerr.EPERM
			}
		}
	}
	if !t.MayKill(target, sig) {
		return linuxerr.EPERM
	}

	switch effectiveFlags {
	case linux.PIDFD_SIGNAL_THREAD:
		return target.SendSignal(info)
	case linux.PIDFD_SIGNAL_THREAD_GROUP:
		return target.SendGroupSignal(info)
	case linux.PIDFD_SIGNAL_PROCESS_GROUP:
		tg := target.ThreadGroup()
		if tg.ProcessGroup().Originator() != tg {
			return linuxerr.EINVAL
		}
		return tg.ProcessGroup().SendSignal(info)
	default: // Unreachable.
		t.Warningf("Unexpected error in PIDFDSendSignal with flags %d", flags)
		return linuxerr.EINVAL
	}
}

// PIDFDTask returns the task associated with the pidfd represented by vfsfd.
// If the vfsfd is neither a true pidfd nor a /proc/pid node, an error is returned.
func PIDFDTask(vfsfd *vfs.FileDescription) (*Task, error) {
	pfd, ok := vfsfd.Impl().(*pidFD)
	if ok { // vfsfd is a true pidfd (a product of pidfd_open() or clone3(CLONE_PIDFD)).
		return pfd.liveTask()
	}
	t, err := taskFromProcPIDFD(vfsfd) // Maybe it's a classic pidfd from /proc/$pid.
	if err != nil {
		return nil, err
	}
	if t.ExitState() >= TaskExitZombie {
		return nil, linuxerr.ESRCH
	}
	return t, nil
}

// ObservedTIDsForPIDFD returns a slice of Thread IDs of the target task represented by
// vfsfd in all its ancestral pidns's ending at the pidns of the observing task t, with
// deeper pidns tids earlier in the slice.
// Returns an error if vfsfd is not a true pidfd.
func ObservedTIDsForPIDFD(vfsfd *vfs.FileDescription, t *Task) ([]int32, error) {
	pfd, ok := vfsfd.Impl().(*pidFD)
	if !ok {
		return nil, linuxerr.EBADF
	}
	target := pfd.pid.t.Load()
	if target == nil {
		return []int32{-1}, nil // target is reaped.
	}

	tNS := t.PIDNamespace()
	targetNS := target.PIDNamespace()
	tidAtT := tNS.IDOfTask(target)
	if tidAtT == 0 {
		return []int32{0}, nil
	}

	var nspids []int32
	for cur := targetNS; cur != nil; cur = cur.parent {
		nspids = append(nspids, int32(cur.IDOfTask(target)))
		if cur == tNS {
			break // Stop at the observing task's pidns.
		}
	}
	return nspids, nil
}
