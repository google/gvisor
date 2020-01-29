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

//+build amd64

package linux

import (
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/binary"
	"gvisor.dev/gvisor/pkg/sentry/fs"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/usermem"
)

// copyOutStat copies the attributes (sattr, uattr) to the struct stat at
// address dst in t's address space. It encodes the stat struct to bytes
// manually, as stat() is a very common syscall for many applications, and
// t.CopyObjectOut has noticeable performance impact due to its many slice
// allocations and use of reflection.
func copyOutStat(t *kernel.Task, dst usermem.Addr, sattr fs.StableAttr, uattr fs.UnstableAttr) error {
	b := t.CopyScratchBuffer(int(linux.SizeOfStat))[:0]

	// Dev (uint64)
	b = binary.AppendUint64(b, usermem.ByteOrder, uint64(sattr.DeviceID))
	// Ino (uint64)
	b = binary.AppendUint64(b, usermem.ByteOrder, uint64(sattr.InodeID))
	// Nlink (uint64)
	b = binary.AppendUint64(b, usermem.ByteOrder, uattr.Links)
	// Mode (uint32)
	b = binary.AppendUint32(b, usermem.ByteOrder, sattr.Type.LinuxType()|uint32(uattr.Perms.LinuxMode()))
	// UID (uint32)
	b = binary.AppendUint32(b, usermem.ByteOrder, uint32(uattr.Owner.UID.In(t.UserNamespace()).OrOverflow()))
	// GID (uint32)
	b = binary.AppendUint32(b, usermem.ByteOrder, uint32(uattr.Owner.GID.In(t.UserNamespace()).OrOverflow()))
	// Padding (uint32)
	b = binary.AppendUint32(b, usermem.ByteOrder, 0)
	// Rdev (uint64)
	b = binary.AppendUint64(b, usermem.ByteOrder, uint64(linux.MakeDeviceID(sattr.DeviceFileMajor, sattr.DeviceFileMinor)))
	// Size (uint64)
	b = binary.AppendUint64(b, usermem.ByteOrder, uint64(uattr.Size))
	// Blksize (uint64)
	b = binary.AppendUint64(b, usermem.ByteOrder, uint64(sattr.BlockSize))
	// Blocks (uint64)
	b = binary.AppendUint64(b, usermem.ByteOrder, uint64(uattr.Usage/512))

	// ATime
	atime := uattr.AccessTime.Timespec()
	b = binary.AppendUint64(b, usermem.ByteOrder, uint64(atime.Sec))
	b = binary.AppendUint64(b, usermem.ByteOrder, uint64(atime.Nsec))

	// MTime
	mtime := uattr.ModificationTime.Timespec()
	b = binary.AppendUint64(b, usermem.ByteOrder, uint64(mtime.Sec))
	b = binary.AppendUint64(b, usermem.ByteOrder, uint64(mtime.Nsec))

	// CTime
	ctime := uattr.StatusChangeTime.Timespec()
	b = binary.AppendUint64(b, usermem.ByteOrder, uint64(ctime.Sec))
	b = binary.AppendUint64(b, usermem.ByteOrder, uint64(ctime.Nsec))

	_, err := t.CopyOutBytes(dst, b)
	return err
}
