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

package lisafs

import (
	"fmt"
	"structs"
	"time"

	"gvisor.dev/gvisor/pkg/abi/linux"
)

// StatxTimestamp represents struct statx_timestamp.
//
// +marshal
type StatxTimestamp struct {
	_    structs.HostLayout
	Sec  int64
	Nsec uint32
	_    int32
}

// ToTime returns the Go time.Time representation.
func (sxts StatxTimestamp) ToTime() time.Time {
	return time.Unix(sxts.Sec, int64(sxts.Nsec))
}

// ToNsec returns the nanosecond representation.
func (sxts StatxTimestamp) ToNsec() int64 {
	return int64(sxts.Sec)*1e9 + int64(sxts.Nsec)
}

// Statx represents struct statx. This is a protocol-stable version of
// linux.Statx. It must not be changed, as it determines the lisafs wire
// format.
//
// +marshal boundCheck slice:StatxSlice
type Statx struct {
	_              structs.HostLayout
	Mask           uint32
	Blksize        uint32
	Attributes     uint64
	Nlink          uint32
	UID            uint32
	GID            uint32
	Mode           uint16
	_              uint16
	Ino            uint64
	Size           uint64
	Blocks         uint64
	AttributesMask uint64
	Atime          StatxTimestamp
	Btime          StatxTimestamp
	Ctime          StatxTimestamp
	Mtime          StatxTimestamp
	RdevMajor      uint32
	RdevMinor      uint32
	DevMajor       uint32
	DevMinor       uint32
}

// ToLinuxStatx returns a linux.Statx representation of s.
func (s Statx) ToLinuxStatx() linux.Statx {
	return linux.Statx{
		Mask:           s.Mask,
		Blksize:        s.Blksize,
		Attributes:     s.Attributes,
		Nlink:          s.Nlink,
		UID:            s.UID,
		GID:            s.GID,
		Mode:           s.Mode,
		Ino:            s.Ino,
		Size:           s.Size,
		Blocks:         s.Blocks,
		AttributesMask: s.AttributesMask,
		Atime:          linux.StatxTimestamp{Sec: s.Atime.Sec, Nsec: s.Atime.Nsec},
		Btime:          linux.StatxTimestamp{Sec: s.Btime.Sec, Nsec: s.Btime.Nsec},
		Ctime:          linux.StatxTimestamp{Sec: s.Ctime.Sec, Nsec: s.Ctime.Nsec},
		Mtime:          linux.StatxTimestamp{Sec: s.Mtime.Sec, Nsec: s.Mtime.Nsec},
		RdevMajor:      s.RdevMajor,
		RdevMinor:      s.RdevMinor,
		DevMajor:       s.DevMajor,
		DevMinor:       s.DevMinor,
	}
}

// NsecToStatxTimestamp translates nanoseconds to StatxTimestamp.
func NsecToStatxTimestamp(nsec int64) (ts StatxTimestamp) {
	return StatxTimestamp{
		Sec:  nsec / 1e9,
		Nsec: uint32(nsec % 1e9),
	}
}

// String implements fmt.Stringer.String.
func (s *Statx) String() string {
	return fmt.Sprintf("Statx{Mask: %#x, Mode: %s, UID: %d, GID: %d, Ino: %d, DevMajor: %d, DevMinor: %d, Size: %d, Blocks: %d, Blksize: %d, Nlink: %d, Atime: %s, Btime: %s, Ctime: %s, Mtime: %s, Attributes: %d, AttributesMask: %d, RdevMajor: %d, RdevMinor: %d}",
		s.Mask, linux.FileMode(s.Mode), s.UID, s.GID, s.Ino, s.DevMajor, s.DevMinor, s.Size, s.Blocks, s.Blksize, s.Nlink, s.Atime.ToTime(), s.Btime.ToTime(), s.Ctime.ToTime(), s.Mtime.ToTime(), s.Attributes, s.AttributesMask, s.RdevMajor, s.RdevMinor)
}

// SizeOfStatx is the size of a Statx struct.
var SizeOfStatx = (*Statx)(nil).SizeBytes()
