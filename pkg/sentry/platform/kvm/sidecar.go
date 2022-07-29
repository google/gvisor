// Copyright 2022 The gVisor Authors.
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

package kvm

import (
	"runtime"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/atomicbitops"
	"gvisor.dev/gvisor/pkg/procid"
)

type sidecar struct {
	syscallThreadState  atomicbitops.Uint32
	syscallSlowPath     atomicbitops.Uint32
	syscallThreadKilled atomicbitops.Uint32

	locked atomicbitops.Uint32

	tid     uint64
	vcpuTID uint64

	sysno uintptr
	args  [6]uintptr
	ret   uintptr
}

// spinloop is implemented in assembly.
func spinloop()

var schedCoreTaggingSupported bool = func() bool {
	if _, _, errno := unix.RawSyscall6(
		unix.SYS_PRCTL, unix.PR_SCHED_CORE,
		unix.PR_SCHED_CORE_GET,
		0, 0, 0, 0); errno == unix.EINVAL {
		return false
	}
	return true
}()

//go:nosplit
func (s *sidecar) bindSidecar() {
	if !schedCoreTaggingSupported {
		return
	}

	tid := procid.Current()
	if tid != s.vcpuTID {
		s.vcpuTID = tid
		if _, _, errno := unix.RawSyscall6(
			unix.SYS_PRCTL, unix.PR_SCHED_CORE,
			unix.PR_SCHED_CORE_CREATE,
			0, 0, 0, 0); errno != 0 {
			throw("error creating core scheduling cookie")
		}
		s.sysno = unix.SYS_PRCTL
		s.args[0] = unix.PR_SCHED_CORE
		s.args[1] = unix.PR_SCHED_CORE_SHARE_FROM
		s.args[2] = uintptr(tid)
		s.args[3] = 0
		s.args[4] = 0
		s.args[5] = 0
		if !s.syscallThreadState.CompareAndSwap(sidecarIdle, sidecarBusy) {
			return
		}

		for s.syscallThreadState.Load() == sidecarBusy {
			spinloop()
		}
		if s.ret != 0 {
			throw("error setting core scheduling cookie")
		}
	}
}

//go:nosplit
func (s *sidecar) kick() {
	if s.syscallThreadState.CompareAndSwap(sidecarStopped, sidecarIdle) {
		futexWakeUint32(s.syscallThreadState.Ptr())
	}

	s.bindSidecar()
}

//go:nosplit
func (s *sidecar) fini() {
	s.syscallThreadKilled.Store(1)
	if s.syscallThreadState.CompareAndSwap(sidecarStopped, sidecarReleased) {
		futexWakeUint32(s.syscallThreadState.Ptr())
	}
}

//go:nosplit
func (s *sidecar) stop() bool {
	return s.syscallThreadState.CompareAndSwap(sidecarIdle, sidecarStopped)
}

const sidecarLoopSlowCheck = 1000000
const deepSleepTimeout = 1000000 * 2 // 1ms for 2GHz CPU.

//go:nosplit
func (s *sidecar) loop() {
	start := cputicks()
	i := 0
	for {
		i++
		state := s.syscallThreadState.Load()
		if state == sidecarStopped || s.syscallThreadKilled.Load() != 0 {
			break
		}
		if i%sidecarLoopSlowCheck == 0 {
			if cputicks()-start > deepSleepTimeout &&
				s.syscallThreadState.CompareAndSwap(sidecarIdle, sidecarStopped) {
				break
			}
		}
		if state != sidecarBusy {
			spinloop()
			continue
		}

		start = cputicks()
		r, _, errno := unix.RawSyscall6(
			s.sysno,
			s.args[0],
			s.args[1],
			s.args[2],
			s.args[3],
			s.args[4],
			s.args[5])
		if errno != 0 {
			s.ret = uintptr(-errno)
		} else {
			s.ret = r
		}
		prev := s.syscallThreadState.Swap(sidecarIdle)
		if prev != sidecarBusy {
			throw("invalide sidecar state")
		}
		if s.syscallSlowPath.Load() != 0 {
			futexWakeUint32(s.syscallThreadState.Ptr())
		}
	}
}

func newSidecar() *sidecar {
	var syscallLoopStarted atomicbitops.Uint32
	sidecar := &sidecar{}
	go func() {
		runtime.LockOSThread()
		entersyscall()
		redpill()
		sidecar.tid = procid.Current()
		syscallLoopStarted.Store(1)
		for {
			futexWaitWhileUint32(&sidecar.syscallThreadState, sidecarStopped)
			sidecar.loop()
			if sidecar.syscallThreadKilled.Load() != 0 {
				break
			}
		}
		exitsyscall()
		runtime.UnlockOSThread()
	}()
	// Need to wait when the sidecar loop starts running, otherwise we can
	// ask to run a scheduler syscall (e.g. futex) and we will be stuck.
	for syscallLoopStarted.Load() == 0 {
		runtime.Gosched()
	}
	return sidecar
}
