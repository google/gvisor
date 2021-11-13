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

package time

import (
	"syscall"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
)

func TestClockGetTime(t *testing.T) {
	ts := unix.Timespec{}
	if ret := vdsoClockGettime(linux.CLOCK_MONOTONIC, &ts); ret != 0 {
		t.Fatalf("Unexpected error code: %v", ret)
	}
	sts := unix.Timespec{}
	if _, _, errno := unix.RawSyscall(unix.SYS_CLOCK_GETTIME,
		uintptr(linux.CLOCK_MONOTONIC),
		uintptr(unsafe.Pointer(&sts)), 0); errno != 0 {
		t.Fatalf("Unexpected error code: %v", errno)
	}
	// Check that ts.Sec is in [sts.Sec, sts.Sec + 5].
	if sts.Sec < ts.Sec || sts.Sec > ts.Sec+5 {
		t.Fatalf("Unexpected delta: vdso %+v syscall %+v", ts, sts)
	}
}

func TestClockGetTimeEINVAL(t *testing.T) {
	ts := unix.Timespec{}
	if ret := vdsoClockGettime(-1, &ts); ret != -int(syscall.EINVAL) {
		t.Fatalf("Unexpected error code: %v", ret)
	}
}
