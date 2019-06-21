// Copyright 2019 The gVisor Authors.
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

// +build linux

package flipcall

import (
	"fmt"
	"math"
	"sync/atomic"
	"syscall"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/log"
)

func (ep *Endpoint) doFutexRoundTrip() error {
	ourSeq, err := ep.doFutexNotifySeq()
	if err != nil {
		return err
	}
	return ep.doFutexWaitSeq(ourSeq)
}

func (ep *Endpoint) doFutexWaitFirst() error {
	return ep.doFutexWaitSeq(0)
}

func (ep *Endpoint) doFutexNotifyLast() error {
	_, err := ep.doFutexNotifySeq()
	return err
}

func (ep *Endpoint) doFutexNotifySeq() (uint32, error) {
	ourSeq := atomic.AddUint32(ep.seq(), 1)
	if err := ep.futexWake(1); err != nil {
		return ourSeq, fmt.Errorf("failed to FUTEX_WAKE peer Endpoint: %v", err)
	}
	return ourSeq, nil
}

func (ep *Endpoint) doFutexWaitSeq(prevSeq uint32) error {
	nextSeq := prevSeq + 1
	for {
		if ep.isShutdown() {
			return endpointShutdownError{}
		}
		if err := ep.futexWait(prevSeq); err != nil {
			return fmt.Errorf("failed to FUTEX_WAIT for peer Endpoint: %v", err)
		}
		seq := atomic.LoadUint32(ep.seq())
		if seq == nextSeq {
			return nil
		}
		if seq != prevSeq {
			return fmt.Errorf("invalid packet sequence number %d (expected %d or %d)", seq, prevSeq, nextSeq)
		}
	}
}

func (ep *Endpoint) doFutexInterruptForShutdown() {
	// Wake MaxInt32 threads to prevent a malicious or broken peer from
	// swallowing our wakeup by FUTEX_WAITing from multiple threads.
	if err := ep.futexWake(math.MaxInt32); err != nil {
		log.Warningf("failed to FUTEX_WAKE Endpoint: %v", err)
	}
}

func (ep *Endpoint) futexWake(numThreads int32) error {
	if _, _, e := syscall.RawSyscall(syscall.SYS_FUTEX, uintptr(ep.packet), linux.FUTEX_WAKE, uintptr(numThreads)); e != 0 {
		return e
	}
	return nil
}

func (ep *Endpoint) futexWait(seq uint32) error {
	_, _, e := syscall.Syscall6(syscall.SYS_FUTEX, uintptr(ep.packet), linux.FUTEX_WAIT, uintptr(seq), 0, 0, 0)
	if e != 0 && e != syscall.EAGAIN && e != syscall.EINTR {
		return e
	}
	return nil
}
