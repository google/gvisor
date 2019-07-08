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

import "gvisor.dev/gvisor/pkg/sentry/kernel/time"

// InodeNew represents ext4 inode structure which can be bigger than
// OldInodeSize. The actual size of this struct should be determined using
// inode.ExtraInodeSize. Accessing any field here should be verified with the
// actual size. The extra space between the end of the inode struct and end of
// the inode record can be used to store extended attr.
//
// If the TimeExtra fields are in scope, the lower 2 bits of those are used
// to extend their counter part to be 34 bits wide; the rest (upper) 30 bits
// are used to provide nanoscond precision. Hence, these timestamps will now
// overflow in May 2446.
// See https://www.kernel.org/doc/html/latest/filesystems/ext4/dynamic.html#inode-timestamps.
type InodeNew struct {
	InodeOld

	ExtraInodeSize        uint16
	ChecksumHi            uint16
	ChangeTimeExtra       uint32
	ModificationTimeExtra uint32
	AccessTimeExtra       uint32
	CreationTime          uint32
	CreationTimeExtra     uint32
	VersionHi             uint32
	ProjectID             uint32
}

// Compiles only if InodeNew implements Inode.
var _ Inode = (*InodeNew)(nil)

// fromExtraTime decodes the extra time and constructs the kernel time struct
// with nanosecond precision.
func fromExtraTime(lo int32, extra uint32) time.Time {
	// See description above InodeNew for format.
	seconds := (int64(extra&0x3) << 32) + int64(lo)
	nanoseconds := int64(extra >> 2)
	return time.FromUnix(seconds, nanoseconds)
}

// Only override methods which change due to ext4 specific fields.

// Size implements Inode.Size.
func (in *InodeNew) Size() uint64 {
	return (uint64(in.SizeHi) << 32) | uint64(in.SizeLo)
}

// InodeSize implements Inode.InodeSize.
func (in *InodeNew) InodeSize() uint16 {
	return oldInodeSize + in.ExtraInodeSize
}

// ChangeTime implements Inode.ChangeTime.
func (in *InodeNew) ChangeTime() time.Time {
	// Apply new timestamp logic if inode.ChangeTimeExtra is in scope.
	if in.ExtraInodeSize >= 8 {
		return fromExtraTime(in.ChangeTimeRaw, in.ChangeTimeExtra)
	}

	return in.InodeOld.ChangeTime()
}

// ModificationTime implements Inode.ModificationTime.
func (in *InodeNew) ModificationTime() time.Time {
	// Apply new timestamp logic if inode.ModificationTimeExtra is in scope.
	if in.ExtraInodeSize >= 12 {
		return fromExtraTime(in.ModificationTimeRaw, in.ModificationTimeExtra)
	}

	return in.InodeOld.ModificationTime()
}

// AccessTime implements Inode.AccessTime.
func (in *InodeNew) AccessTime() time.Time {
	// Apply new timestamp logic if inode.AccessTimeExtra is in scope.
	if in.ExtraInodeSize >= 16 {
		return fromExtraTime(in.AccessTimeRaw, in.AccessTimeExtra)
	}

	return in.InodeOld.AccessTime()
}
