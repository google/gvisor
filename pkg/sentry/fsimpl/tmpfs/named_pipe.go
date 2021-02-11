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
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/kernel/pipe"
)

// +stateify savable
type namedPipe struct {
	inode inode

	pipe *pipe.VFSPipe
}

// Preconditions:
// * fs.mu must be locked.
// * rp.Mount().CheckBeginWrite() has been called successfully.
func (fs *filesystem) newNamedPipe(kuid auth.KUID, kgid auth.KGID, mode linux.FileMode, parentDir *directory) *inode {
	file := &namedPipe{pipe: pipe.NewVFSPipe(true /* isNamed */, pipe.DefaultPipeSize)}
	file.inode.init(file, fs, kuid, kgid, linux.S_IFIFO|mode, parentDir)
	file.inode.nlink = 1 // Only the parent has a link.
	return &file.inode
}
