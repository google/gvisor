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

package tmpfs

import (
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/atomicbitops"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
)

// +stateify savable
type symlink struct {
	inode  inode
	target string // immutable
}

func (fs *filesystem) newSymlink(kuid auth.KUID, kgid auth.KGID, mode linux.FileMode, target string, parentDir *directory) *inode {
	link := &symlink{
		target: target,
	}
	link.inode.init(link, fs, kuid, kgid, linux.S_IFLNK|mode, parentDir)
	link.inode.nlink = atomicbitops.FromUint32(1) // from parent directory
	return &link.inode
}

// O_PATH is unimplemented, so there's no way to get a FileDescription
// representing a symlink yet.
