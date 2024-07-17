// Copyright 2021 The gVisor Authors.
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

package systrap

import (
	"fmt"
	"os"
	"sync/atomic"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/seccomp"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/pgalloc"
	"gvisor.dev/gvisor/pkg/sentry/platform/systrap/sysmsg"
	"gvisor.dev/gvisor/pkg/sentry/usage"
)

// The syscall message consists of sentry and stub messages.
const syscallThreadMessageSize = hostarch.PageSize * 2

// syscallThread implements the process of calling syscalls in a stub process.
//
// Each syscall thread owns a shared memory region to communicate with the
// Sentry. This region consists of two pages. The first page called
// sentryMessage is mapped as read-only in the stub address space. The second
// page called stubMessage is mapped as read-write in the stub process.
//
// Any memory regions that are mapped as read-write in a stub address space can
// be changed from a user code. This means that we can't trust the content of
// stubMessage, but it is used to receive a syscall return code. Therefore
// syscallThread can be used only in these cases:
//   - If a system call never fails (e.g munmap).
//   - If a system call has to return only one know value or if it fails,
//     it doesn't not reveal any data (e.g. mmap).
type syscallThread struct {
	// subproc is a link to the subprocess which is used to call native
	// system calls and track when a sysmsg thread has to be recreated.
	// Look at getSysmsgThread() for more details.
	subproc *subprocess

	// thread is a thread identifier.
	thread *thread

	// stackRange is the range for the sentry syscall message in the memory
	// file.
	stackRange memmap.FileRange

	// sentryAddr is the address of the shared memory region in the Sentry
	// address space.
	sentryAddr uintptr
	// stubAddr is the address of the shared memory region in the stub
	// address space.
	stubAddr uintptr

	// sentryMessage is the first page of the share message that can't be
	// modified by the stub thread.
	sentryMessage *syscallSentryMessage
	// stubMessage is the second page of the shared message that can be
	// modified by the stub thread.
	stubMessage *syscallStubMessage

	seccompNotify     *os.File
	seccompNotifyResp linux.SeccompNotifResp
}

func (t *syscallThread) init(seccompNotify bool) error {
	// Allocate a new shared memory message.
	opts := pgalloc.AllocOpts{
		Kind: usage.System,
		Dir:  pgalloc.TopDown,
	}
	fr, err := t.subproc.memoryFile.Allocate(syscallThreadMessageSize, opts)
	if err != nil {
		return err
	}

	t.stackRange = fr
	t.stubAddr = stubSysmsgStack + sysmsg.PerThreadMemSize*uintptr(t.thread.sysmsgStackID)
	err = t.mapMessageIntoStub()
	if err != nil {
		t.destroy()
		return err
	}

	if seccompNotify && seccompNotifyIsSupported {
		if t.seccompNotify, err = t.installSeccompNotify(); err != nil {
			t.destroy()
			return fmt.Errorf("failed to install seccomp notify rules: %w", err)
		}
	}

	// Map the stack into the sentry.
	sentryAddr, _, errno := unix.RawSyscall6(
		unix.SYS_MMAP,
		0,
		syscallThreadMessageSize,
		unix.PROT_WRITE|unix.PROT_READ,
		unix.MAP_SHARED|unix.MAP_FILE,
		uintptr(t.subproc.memoryFile.FD()), uintptr(fr.Start))
	if errno != 0 {
		t.destroy()
		return fmt.Errorf("mmap failed: %v", errno)
	}
	t.sentryAddr = sentryAddr

	t.initRequestReplyAddresses(sentryAddr)
	return nil
}

func (t *syscallThread) destroy() {
	if t.sentryAddr != 0 {
		_, _, errno := unix.RawSyscall6(
			unix.SYS_MUNMAP,
			t.sentryAddr,
			syscallThreadMessageSize,
			0, 0, 0, 0)
		if errno != 0 {
			panic(fmt.Sprintf("mumap failed: %v", errno))
		}
	}
	if t.stubAddr != 0 {
		_, err := t.thread.syscallIgnoreInterrupt(&t.thread.initRegs, unix.SYS_MUNMAP,
			arch.SyscallArgument{Value: t.stubAddr},
			arch.SyscallArgument{Value: uintptr(syscallThreadMessageSize)})
		if err != nil {
			panic(fmt.Sprintf("munmap failed: %v", err))
		}
	}
	t.subproc.memoryFile.DecRef(t.stackRange)
	t.subproc.sysmsgStackPool.Put(t.thread.sysmsgStackID)
}

func (t *syscallThread) installSeccompNotify() (*os.File, error) {
	fd, err := t.thread.syscallIgnoreInterrupt(&t.thread.initRegs, seccomp.SYS_SECCOMP,
		arch.SyscallArgument{Value: uintptr(linux.SECCOMP_SET_MODE_FILTER)},
		arch.SyscallArgument{Value: uintptr(linux.SECCOMP_FILTER_FLAG_NEW_LISTENER)},
		arch.SyscallArgument{Value: stubSyscallRules})
	if err != nil {
		return nil, err
	}
	_, _, errno := unix.RawSyscall(unix.SYS_IOCTL, fd, linux.SECCOMP_IOCTL_NOTIF_SET_FLAGS, linux.SECCOMP_USER_NOTIF_FD_SYNC_WAKE_UP)
	if errno != 0 {
		t.thread.Debugf("failed to set SECCOMP_USER_NOTIF_FD_SYNC_WAKE_UP")
	}
	return os.NewFile(fd, "seccomp_notify"), nil
}

// mapMessageIntoStub maps the syscall message into the stub process address space.
func (t *syscallThread) mapMessageIntoStub() error {
	// Map sentryMessage as read-only.
	_, err := t.thread.syscallIgnoreInterrupt(&t.thread.initRegs, unix.SYS_MMAP,
		arch.SyscallArgument{Value: t.stubAddr},
		arch.SyscallArgument{Value: uintptr(hostarch.PageSize)},
		arch.SyscallArgument{Value: uintptr(unix.PROT_READ)},
		arch.SyscallArgument{Value: unix.MAP_SHARED | unix.MAP_FILE | unix.MAP_FIXED},
		arch.SyscallArgument{Value: uintptr(t.subproc.memoryFile.FD())},
		arch.SyscallArgument{Value: uintptr(t.stackRange.Start)})
	if err != nil {
		return err
	}
	// Map stubMessage as read-write.
	_, err = t.thread.syscallIgnoreInterrupt(&t.thread.initRegs, unix.SYS_MMAP,
		arch.SyscallArgument{Value: t.stubAddr + syscallStubMessageOffset},
		arch.SyscallArgument{Value: uintptr(hostarch.PageSize)},
		arch.SyscallArgument{Value: uintptr(unix.PROT_READ | unix.PROT_WRITE)},
		arch.SyscallArgument{Value: unix.MAP_SHARED | unix.MAP_FILE | unix.MAP_FIXED},
		arch.SyscallArgument{Value: uintptr(t.subproc.memoryFile.FD())},
		arch.SyscallArgument{Value: uintptr(t.stackRange.Start + hostarch.PageSize)})
	return err
}

// attach attaches to the stub thread with ptrace and unlock signals.
func (t *syscallThread) attach() error {
	if err := t.thread.attach(); err != nil {
		return err
	}
	// We need to unblock signals, because the TRAP signal is used to run
	// syscalls via ptrace.
	t.unmaskAllSignalsAttached()
	return nil
}

const maxErrno = 4095

func (t *syscallThread) syscall(sysno uintptr, args ...arch.SyscallArgument) (uintptr, error) {
	if t.subproc.dead.Load() {
		return 0, errDeadSubprocess
	}
	sentryMsg := t.sentryMessage
	stubMsg := t.stubMessage
	sentryMsg.sysno = uint64(sysno)
	for i := 0; i < len(sentryMsg.args); i++ {
		if i < len(args) {
			sentryMsg.args[i] = uint64(args[i].Value)
		} else {
			sentryMsg.args[i] = 0
		}
	}

	if t.seccompNotify != nil {
		if errno := t.kickSeccompNotify(); errno != 0 {
			t.thread.kill()
			t.thread.Warningf("failed sending request to syscall thread: %s", errno)
			return 0, errDeadSubprocess
		}
		if err := t.waitForSeccompNotify(); err != nil {
			t.thread.Warningf("failed waiting for seccomp notify: %s", err)
			return 0, errDeadSubprocess
		}
	} else {

		// Notify the syscall thread about a new syscall request.
		atomic.AddUint32(&sentryMsg.state, 1)
		futexWakeUint32(&sentryMsg.state)

		// Wait for reply.
		//
		// futex waits for sentryMsg.state that isn't changed, so it will
		// returns only only when the other side will call FUTEX_WAKE.
		futexWaitWake(&sentryMsg.state, atomic.LoadUint32(&sentryMsg.state))
	}

	errno := -uintptr(stubMsg.ret)
	if errno > 0 && errno < maxErrno {
		return 0, fmt.Errorf("stub syscall (%x, %#v) failed with %w", sysno, args, unix.Errno(errno))
	}

	return uintptr(stubMsg.ret), nil
}
