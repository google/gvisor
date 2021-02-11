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
	"gvisor.dev/gvisor/pkg/sentry/socket/unix/transport"
)

// socketFile is a socket (=S_IFSOCK) tmpfs file.
//
// +stateify savable
type socketFile struct {
	inode inode
	ep    transport.BoundEndpoint
}

func (fs *filesystem) newSocketFile(kuid auth.KUID, kgid auth.KGID, mode linux.FileMode, ep transport.BoundEndpoint, parentDir *directory) *inode {
	file := &socketFile{ep: ep}
	file.inode.init(file, fs, kuid, kgid, mode, parentDir)
	file.inode.nlink = 1 // from parent directory
	return &file.inode
}
