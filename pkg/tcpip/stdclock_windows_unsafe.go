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

//go:build windows && !go1.28
// +build windows,!go1.28

package tcpip

import (
	"syscall"
	"time"
	"unsafe"
)

var (
	// qpcCounter is the address of QueryPerformanceCounter.
	qpcCounter uintptr

	// qpcFrequency is the number of performance counter ticks per second.
	qpcFrequency int64
)

// On Windows, the monotonic clock of the time package reads the interrupt
// time, which only moves when the system timer fires: every 15.6 ms by
// default, and at best every 0.5 ms. TCP takes its RTT samples, and the
// transmit times RACK compares, from Clock.NowMonotonic. With a peer less
// than a tick away, most RTT samples are 0 and segments sent in the same tick
// share a transmit time, so RACK marks segments lost that were not and they
// are retransmitted at once. QueryPerformanceCounter typically moves every
// 100 ns.
//
// From Go 1.28, the monotonic clock of the time package moves every 100 ns
// on Windows too (golang/go@16d46baf6), so this file is only built with
// earlier versions.
func init() {
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	counter := kernel32.NewProc("QueryPerformanceCounter")
	frequency := kernel32.NewProc("QueryPerformanceFrequency")
	if counter.Find() != nil || frequency.Find() != nil {
		return
	}
	var freq int64
	if r, _, _ := syscall.SyscallN(frequency.Addr(), uintptr(unsafe.Pointer(&freq))); r == 0 || freq <= 0 {
		return
	}
	qpcCounter = counter.Addr()
	qpcFrequency = freq
	highResCounter = qpcNow
}

// qpcNow returns the time elapsed since boot, read from
// QueryPerformanceCounter.
func qpcNow() time.Duration {
	var ticks int64
	// QueryPerformanceCounter cannot fail on Windows XP or later.
	syscall.SyscallN(qpcCounter, uintptr(unsafe.Pointer(&ticks)))
	return time.Duration(ticks/qpcFrequency)*time.Second + time.Duration(ticks%qpcFrequency*int64(time.Second)/qpcFrequency)
}
