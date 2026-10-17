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
	"errors"
	"fmt"
	"sync/atomic"
	"unsafe"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/abi/nvgpu"
	"gvisor.dev/gvisor/pkg/hostsyscall"
	"gvisor.dev/gvisor/pkg/sentry/arch"
)

// UVMInitialize implements platform.UVMAddressSpace.
func (s *subprocess) UVMInitialize(hostFD int32, flags uint64) (uint32, error) {
	return s.uvmIoctl(hostFD, nvgpu.UVM_INITIALIZE, func(t *syscallThread) (uintptr, *uint32) {
		params := &t.stubMessage.uvmInitializeParams
		*params = nvgpu.UVM_INITIALIZE_PARAMS{Flags: flags, RMStatus: nvgpu.NV_ERR_INVALID_ARGUMENT}
		return t.stubAddr + syscallStubMessageOffset + unsafe.Offsetof(syscallStubMessage{}.uvmInitializeParams), &params.RMStatus
	})
}

// UVMPopulatePageable implements platform.UVMAddressSpace.
func (s *subprocess) UVMPopulatePageable(hostFD int32, base, length uint64, flags uint32) (uint32, error) {
	return s.uvmIoctl(hostFD, nvgpu.UVM_POPULATE_PAGEABLE, func(t *syscallThread) (uintptr, *uint32) {
		params := &t.stubMessage.uvmPopulatePageableParams
		*params = nvgpu.UVM_POPULATE_PAGEABLE_PARAMS{Base: base, Length: length, Flags: flags, RMStatus: nvgpu.NV_ERR_INVALID_ARGUMENT}
		return t.stubAddr + syscallStubMessageOffset + unsafe.Offsetof(syscallStubMessage{}.uvmPopulatePageableParams), &params.RMStatus
	})
}

// UVMSetPreferredLocation implements platform.UVMAddressSpace.
func (s *subprocess) UVMSetPreferredLocation(hostFD int32, base, length uint64, location [16]byte, cpuNumaNode int32) (uint32, error) {
	return s.uvmIoctl(hostFD, nvgpu.UVM_SET_PREFERRED_LOCATION, func(t *syscallThread) (uintptr, *uint32) {
		params := &t.stubMessage.uvmSetPreferredLocationParams
		*params = nvgpu.UVM_SET_PREFERRED_LOCATION_PARAMS_V550{
			RequestedBase: base, Length: length, PreferredLocation: nvgpu.NvUUID(location),
			PreferredCPUNumaNode: cpuNumaNode, RMStatus: nvgpu.NV_ERR_INVALID_ARGUMENT,
		}
		return t.stubAddr + syscallStubMessageOffset + unsafe.Offsetof(syscallStubMessage{}.uvmSetPreferredLocationParams), &params.RMStatus
	})
}

// uvmIoctl is restricted to the flat, application-controlled structures
// above. It must not accept translated descriptors or pointers into the Sentry:
// guest threads can change the parameter scratch page while an ioctl runs.
func (s *subprocess) uvmIoctl(hostFD int32, cmd uintptr, prepare func(*syscallThread) (uintptr, *uint32)) (uint32, error) {
	if hostFD < 0 {
		return nvgpu.NV_ERR_INVALID_ARGUMENT, unix.EBADF
	}
	status := uint32(nvgpu.NV_ERR_INVALID_ARGUMENT)
	err := s.withAliveRLock(func() error {
		s.syscallThreadMu.Lock()
		defer s.syscallThreadMu.Unlock()
		if s.uvmUnsafe {
			return unix.EIO
		}
		// Serialize against failed thread creation before the driver can
		// retain this mm. It must never contain aliases of recycled backing
		// or become another application's address space.
		s.uvmInitialized.Store(true)

		t := s.syscallThread
		paramsAddr, statusPtr := prepare(t)
		// CLONE_FILES shares hostFD with the stub. The syscall request page is
		// read-only there, protecting the FD, command, and parameter address.
		_, err := t.syscall(unix.SYS_IOCTL,
			arch.SyscallArgument{Value: uintptr(hostFD)},
			arch.SyscallArgument{Value: cmd},
			arch.SyscallArgument{Value: paramsAddr})
		// The scratch page, status, and syscall return are guest-writable.
		// Nothing returned here is used to make a privileged Sentry decision.
		status = *statusPtr
		var errno unix.Errno
		if errors.As(err, &errno) {
			return errno
		}
		return err
	})
	return status, err
}

func (t *syscallThread) initRequestReplyAddresses(sentryStackAddr uintptr) {
	// These are safe as these addresses are mmapped and never moved/gced.
	sentryMessage := (*syscallSentryMessage)(unsafe.Pointer(sentryStackAddr))
	stubMessage := (*syscallStubMessage)(unsafe.Pointer(sentryStackAddr + syscallStubMessageOffset))
	atomic.StoreUint32(&sentryMessage.state, 0)

	t.sentryMessage = sentryMessage
	t.stubMessage = stubMessage
}

// maskAllSignals blocks all signals.
func (t *syscallThread) maskAllSignalsAttached() {
	p := t.thread

	mask := ^uint64(0)
	if errno := hostsyscall.RawSyscallErrno6(unix.SYS_PTRACE, linux.PTRACE_SETSIGMASK, uintptr(p.tid), 8, uintptr(unsafe.Pointer(&mask)), 0, 0); errno != 0 {
		panic(fmt.Sprintf("unable to setmask: %v", errno))
	}
}

// unmaskAllSignals unblocks all signals.
func (t *syscallThread) unmaskAllSignalsAttached() error {
	p := t.thread
	mask := uint64(0)
	if errno := hostsyscall.RawSyscallErrno6(unix.SYS_PTRACE, linux.PTRACE_SETSIGMASK, uintptr(p.tid), 8, uintptr(unsafe.Pointer(&mask)), 0, 0); errno != 0 {
		return fmt.Errorf("unable to setmask: %w", errno)
	}
	return nil
}

func futexWakeUint32(addr *uint32) error {
	if e := hostsyscall.RawSyscallErrno(unix.SYS_FUTEX, uintptr(unsafe.Pointer(addr)), linux.FUTEX_WAKE, 1); e != 0 {
		return fmt.Errorf("failed to FUTEX_WAKE: %v", e)
	}
	return nil
}

func futexWaitForUint32(addr *uint32, targetValue uint32) error {
	for {
		val := atomic.LoadUint32(addr)
		if val == targetValue {
			break
		}

		_, _, e := unix.Syscall6(unix.SYS_FUTEX, uintptr(unsafe.Pointer(addr)), linux.FUTEX_WAIT, uintptr(val), 0, 0, 0)
		if e != 0 && e != unix.EAGAIN && e != unix.EINTR {
			return fmt.Errorf("failed to FUTEX_WAIT: %v", e)
		}
	}
	return nil
}

// futexWaitWake waits when other side will call FUTEX_WAKE. A value of the
// futex word has to be equal to futexValue and it must not be changed.
func futexWaitWake(futexAddr *uint32, futexValue uint32) error {
	for {
		_, _, e := unix.Syscall6(unix.SYS_FUTEX, uintptr(unsafe.Pointer(futexAddr)), linux.FUTEX_WAIT, uintptr(futexValue), 0, 0, 0)
		if e == 0 {
			break
		}
		if e != unix.EAGAIN && e != unix.EINTR {
			return fmt.Errorf("failed to FUTEX_WAIT: %v", e)
		}
	}

	return nil
}

func (t *syscallThread) kickSeccompNotify() unix.Errno {
	errno := hostsyscall.RawSyscallErrno(unix.SYS_IOCTL, uintptr(t.seccompNotify.Fd()),
		uintptr(linux.SECCOMP_IOCTL_NOTIF_SEND),
		uintptr(unsafe.Pointer(&t.seccompNotifyResp)))
	return errno
}

func (t *syscallThread) waitForSeccompNotify() error {
	for {
		req := linux.SeccompNotif{}
		errno := hostsyscall.RawSyscallErrno(unix.SYS_IOCTL, uintptr(t.seccompNotify.Fd()),
			uintptr(linux.SECCOMP_IOCTL_NOTIF_RECV),
			uintptr(unsafe.Pointer(&req)))
		if errno == 0 {
			t.seccompNotifyResp.ID = req.ID
			break
		}
		// ENOENT: the stub thread's notifying syscall was interrupted between
		// the wakeup and the lookup (by the cgroup freezer, say, which kicks
		// every task out of its waits). The syscall restarts and the kernel
		// issues a new notification for it, as notifySeccompThread already
		// expects for SEND: wait for that one.
		if (errno == unix.EINTR || errno == unix.ENOENT) && t.subproc.alive() {
			continue
		}
		t.thread.kill()
		return fmt.Errorf("failed getting response from syscall thread : %w", errno)
	}
	return nil
}
