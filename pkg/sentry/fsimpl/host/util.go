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

func toTimespec(ts linux.StatxTimestamp, omit bool) unix.Timespec {
	if omit {
		return unix.Timespec{
			Sec:  0,
			Nsec: unix.UTIME_OMIT,
		}
	}
	return unix.Timespec{
		Sec:  int64(ts.Sec),
		Nsec: int64(ts.Nsec),
	}
}

func unixToLinuxStatx(s unix.Statx_t) linux.Statx {
	return linux.Statx{
		Mask:           s.Mask,
		Blksize:        s.Blksize,
		Attributes:     s.Attributes,
		Nlink:          s.Nlink,
		UID:            s.Uid,
		GID:            s.Gid,
		Mode:           s.Mode,
		Ino:            s.Ino,
		Size:           s.Size,
		Blocks:         s.Blocks,
		AttributesMask: s.Attributes_mask,
		Atime:          unixToLinuxStatxTimestamp(s.Atime),
		Btime:          unixToLinuxStatxTimestamp(s.Btime),
		Ctime:          unixToLinuxStatxTimestamp(s.Ctime),
		Mtime:          unixToLinuxStatxTimestamp(s.Mtime),
		RdevMajor:      s.Rdev_major,
		RdevMinor:      s.Rdev_minor,
		DevMajor:       s.Dev_major,
		DevMinor:       s.Dev_minor,
	}
}

func unixToLinuxStatxTimestamp(ts unix.StatxTimestamp) linux.StatxTimestamp {
	return linux.StatxTimestamp{Sec: ts.Sec, Nsec: ts.Nsec}
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
