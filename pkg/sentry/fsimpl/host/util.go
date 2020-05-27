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
	"syscall"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/syserror"
)

func toTimespec(ts linux.StatxTimestamp, omit bool) syscall.Timespec {
	if omit {
		return syscall.Timespec{
			Sec:  0,
			Nsec: unix.UTIME_OMIT,
		}
	}
	return syscall.Timespec{
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

// wouldBlock returns true for file types that can return EWOULDBLOCK
// for blocking operations, e.g. pipes, character devices, and sockets.
func wouldBlock(fileType uint32) bool {
	return fileType == syscall.S_IFIFO || fileType == syscall.S_IFCHR || fileType == syscall.S_IFSOCK
}

// canMap returns true if a file with fileType is allowed to be memory mapped.
// This is ported over from VFS1, but it's probably not the best way for us
// to check if a file can be memory mapped.
func canMap(fileType uint32) bool {
	// TODO(gvisor.dev/issue/1672): Also allow "special files" to be mapped (see fs/host:canMap()).
	//
	// TODO(b/38213152): Some obscure character devices can be mapped.
	return fileType == syscall.S_IFREG
}

// isBlockError checks if an error is EAGAIN or EWOULDBLOCK.
// If so, they can be transformed into syserror.ErrWouldBlock.
func isBlockError(err error) bool {
	return err == syserror.EAGAIN || err == syserror.EWOULDBLOCK
}
