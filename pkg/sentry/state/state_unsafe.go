// Copyright 2018 Google LLC
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

package state

import (
	"fmt"
	"syscall"
	"time"
	"unsafe"

	"gvisor.googlesource.com/gvisor/pkg/abi/linux"
)

// CPUTime returns the CPU time usage by Sentry and app.
func CPUTime() (time.Duration, error) {
	var ts syscall.Timespec
	_, _, errno := syscall.RawSyscall(syscall.SYS_CLOCK_GETTIME, uintptr(linux.CLOCK_PROCESS_CPUTIME_ID), uintptr(unsafe.Pointer(&ts)), 0)
	if errno != 0 {
		return 0, fmt.Errorf("failed calling clock_gettime(CLOCK_PROCESS_CPUTIME_ID): errno=%d", errno)
	}
	return time.Duration(ts.Nano()), nil
}
