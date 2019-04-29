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

package time

import (
	"syscall"
	"unsafe"
)

// syscallTSCReferenceClocks is the standard referenceClocks, collecting
// samples using CLOCK_GETTIME and RDTSC.
type syscallTSCReferenceClocks struct {
	tscCycleClock
}

// Sample implements sampler.Sample.
func (syscallTSCReferenceClocks) Sample(c ClockID) (sample, error) {
	var s sample

	s.before = Rdtsc()

	// Don't call clockGettime to avoid a call which may call morestack.
	var ts syscall.Timespec
	_, _, e := syscall.RawSyscall(syscall.SYS_CLOCK_GETTIME, uintptr(c), uintptr(unsafe.Pointer(&ts)), 0)
	if e != 0 {
		return sample{}, e
	}

	s.after = Rdtsc()
	s.ref = ReferenceNS(ts.Nano())

	return s, nil
}

// clockGettime calls SYS_CLOCK_GETTIME, returning time in nanoseconds.
func clockGettime(c ClockID) (ReferenceNS, error) {
	var ts syscall.Timespec
	_, _, e := syscall.RawSyscall(syscall.SYS_CLOCK_GETTIME, uintptr(c), uintptr(unsafe.Pointer(&ts)), 0)
	if e != 0 {
		return 0, e
	}

	return ReferenceNS(ts.Nano()), nil
}
