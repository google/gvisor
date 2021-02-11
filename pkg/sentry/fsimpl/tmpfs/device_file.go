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

func (fs *filesystem) newDeviceFile(kuid auth.KUID, kgid auth.KGID, mode linux.FileMode, kind vfs.DeviceKind, major, minor uint32, parentDir *directory) *inode {
	file := &deviceFile{
		kind:  kind,
		major: major,
		minor: minor,
	}
	switch kind {
	case vfs.BlockDevice:
		mode |= linux.S_IFBLK
	case vfs.CharDevice:
		mode |= linux.S_IFCHR
	default:
		panic(fmt.Sprintf("invalid DeviceKind: %v", kind))
	}
	file.inode.init(file, fs, kuid, kgid, mode, parentDir)
	file.inode.nlink = 1 // from parent directory
	return &file.inode
}
