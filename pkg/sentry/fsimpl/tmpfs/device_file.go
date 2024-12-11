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

package tmpfs

import (
	"fmt"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/atomicbitops"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

// +stateify savable
type deviceFile struct {
	inode inode
	kind  vfs.DeviceKind
	major uint32
	minor uint32
}

func isOvlWhiteoutDev(mode linux.FileMode, major, minor uint32) bool {
	return mode.FileType() == linux.S_IFCHR &&
		mode.Permissions() == linux.WHITEOUT_MODE &&
		linux.MakeDeviceID(uint16(major), minor) == linux.WHITEOUT_DEV
}

// Precondition: fs.mu must be locked for writing.
func (fs *filesystem) newDeviceFileLocked(kuid auth.KUID, kgid auth.KGID, mode linux.FileMode, major, minor uint32, parentDir *directory) *inode {
	ovlWhiteout := isOvlWhiteoutDev(mode, major, minor)
	if ovlWhiteout && fs.ovlWhiteout != nil {
		// If reusing the same inode, acts like a hard link.
		fs.ovlWhiteout.inode.incLinksLocked()
		return &fs.ovlWhiteout.inode
	}
	file := &deviceFile{
		major: major,
		minor: minor,
	}
	switch mode.FileType() {
	case linux.S_IFBLK:
		file.kind = vfs.BlockDevice
	case linux.S_IFCHR:
		file.kind = vfs.CharDevice
	default:
		panic(fmt.Sprintf("invalid file type for device file: %s", mode))
	}
	file.inode.init(file, fs, kuid, kgid, mode, parentDir)
	file.inode.nlink = atomicbitops.FromUint32(1) // from parent directory
	if ovlWhiteout {
		fs.ovlWhiteout = file
		// An extra link is held by fs, so nlink doesn't fall to 0.
		file.inode.incLinksLocked()
	}
	return &file.inode
}
