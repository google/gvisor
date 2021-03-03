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

package host

import (
	"unsafe"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/sentry/fs"
	ktime "gvisor.dev/gvisor/pkg/sentry/kernel/time"
)

// NulByte is a single NUL byte. It is passed to readlinkat as an empty string.
var NulByte byte = '\x00'

func readLink(fd int) (string, error) {
	// Buffer sizing copied from os.Readlink.
	for l := 128; ; l *= 2 {
		b := make([]byte, l)
		n, _, errno := unix.Syscall6(
			unix.SYS_READLINKAT,
			uintptr(fd),
			uintptr(unsafe.Pointer(&NulByte)), // ""
			uintptr(unsafe.Pointer(&b[0])),
			uintptr(l),
			0, 0)
		if errno != 0 {
			return "", errno
		}
		if n < uintptr(l) {
			return string(b[:n]), nil
		}
	}
}

func timespecFromTimestamp(t ktime.Time, omit, setSysTime bool) unix.Timespec {
	if omit {
		return unix.Timespec{0, linux.UTIME_OMIT}
	}
	if setSysTime {
		return unix.Timespec{0, linux.UTIME_NOW}
	}
	return unix.NsecToTimespec(t.Nanoseconds())
}

func setTimestamps(fd int, ts fs.TimeSpec) error {
	if ts.ATimeOmit && ts.MTimeOmit {
		return nil
	}
	var sts [2]unix.Timespec
	sts[0] = timespecFromTimestamp(ts.ATime, ts.ATimeOmit, ts.ATimeSetSystemTime)
	sts[1] = timespecFromTimestamp(ts.MTime, ts.MTimeOmit, ts.MTimeSetSystemTime)
	_, _, errno := unix.Syscall6(
		unix.SYS_UTIMENSAT,
		uintptr(fd),
		0, /* path */
		uintptr(unsafe.Pointer(&sts)),
		0, /* flags */
		0, 0)
	if errno != 0 {
		return errno
	}
	return nil
}
