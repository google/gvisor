// Copyright 2019 The gVisor Authors.
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

package disklayout

import (
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/kernel/time"
)

const (
	// oldInodeSize is the inode size in ext2/ext3.
	oldInodeSize = 128
)

// InodeOld implements Inode interface. It emulates ext2/ext3 inode struct.
// Inode struct size and record size are both 128 bytes for this.
//
// All fields representing time are in seconds since the epoch. Which means that
// they will overflow in January 2038.
type InodeOld struct {
	ModeRaw uint16
	UIDLo   uint16
	SizeLo  uint32

	// The time fields are signed integers because they could be negative to
	// represent time before the epoch.
	AccessTimeRaw       int32
	ChangeTimeRaw       int32
	ModificationTimeRaw int32
	DeletionTimeRaw     int32

	GIDLo         uint16
	LinksCountRaw uint16
	BlocksCountLo uint32
	FlagsRaw      uint32
	VersionLo     uint32 // This is OS dependent.
	DataRaw       [60]byte
	Generation    uint32
	FileACLLo     uint32
	SizeHi        uint32
	ObsoFaddr     uint32

	// OS dependent fields have been inlined here.
	BlocksCountHi uint16
	FileACLHi     uint16
	UIDHi         uint16
	GIDHi         uint16
	ChecksumLo    uint16
	_             uint16
}

// Compiles only if InodeOld implements Inode.
var _ Inode = (*InodeOld)(nil)

// Mode implements Inode.Mode.
func (in *InodeOld) Mode() linux.FileMode { return linux.FileMode(in.ModeRaw) }

// UID implements Inode.UID.
func (in *InodeOld) UID() auth.KUID {
	return auth.KUID((uint32(in.UIDHi) << 16) | uint32(in.UIDLo))
}

// GID implements Inode.GID.
func (in *InodeOld) GID() auth.KGID {
	return auth.KGID((uint32(in.GIDHi) << 16) | uint32(in.GIDLo))
}

// Size implements Inode.Size.
func (in *InodeOld) Size() uint64 {
	// In ext2/ext3, in.SizeHi did not exist, it was instead named in.DirACL.
	return uint64(in.SizeLo)
}

// InodeSize implements Inode.InodeSize.
func (in *InodeOld) InodeSize() uint16 { return oldInodeSize }

// AccessTime implements Inode.AccessTime.
func (in *InodeOld) AccessTime() time.Time {
	return time.FromUnix(int64(in.AccessTimeRaw), 0)
}

// ChangeTime implements Inode.ChangeTime.
func (in *InodeOld) ChangeTime() time.Time {
	return time.FromUnix(int64(in.ChangeTimeRaw), 0)
}

// ModificationTime implements Inode.ModificationTime.
func (in *InodeOld) ModificationTime() time.Time {
	return time.FromUnix(int64(in.ModificationTimeRaw), 0)
}

// DeletionTime implements Inode.DeletionTime.
func (in *InodeOld) DeletionTime() time.Time {
	return time.FromUnix(int64(in.DeletionTimeRaw), 0)
}

// LinksCount implements Inode.LinksCount.
func (in *InodeOld) LinksCount() uint16 { return in.LinksCountRaw }

// Flags implements Inode.Flags.
func (in *InodeOld) Flags() InodeFlags { return InodeFlagsFromInt(in.FlagsRaw) }

// Data implements Inode.Data.
func (in *InodeOld) Data() []byte { return in.DataRaw[:] }
