// Copyright 2020 The gVisor Authors.
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
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/syserror"
)

func toTimespec(ts linux.StatxTimestamp, omit bool) unix.Timespec {
	if omit {
		return unix.Timespec{
			Sec:  0,
			Nsec: unix.UTIME_OMIT,
		}
	}
	return unix.Timespec{
		Sec:  ts.Sec,
		Nsec: int64(ts.Nsec),
	}
}

func unixToLinuxStatxTimestamp(ts unix.StatxTimestamp) linux.StatxTimestamp {
	return linux.StatxTimestamp{Sec: ts.Sec, Nsec: ts.Nsec}
}

func timespecToStatxTimestamp(ts unix.Timespec) linux.StatxTimestamp {
	return linux.StatxTimestamp{Sec: int64(ts.Sec), Nsec: uint32(ts.Nsec)}
}

// isBlockError checks if an error is EAGAIN or EWOULDBLOCK.
// If so, they can be transformed into syserror.ErrWouldBlock.
func isBlockError(err error) bool {
	return err == syserror.EAGAIN || err == syserror.EWOULDBLOCK
}
