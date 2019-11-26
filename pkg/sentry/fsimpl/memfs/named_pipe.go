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

package memfs

import (
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/sentry/context"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/kernel/pipe"
	"gvisor.dev/gvisor/pkg/sentry/usermem"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

type namedPipe struct {
	inode inode

	pipe *pipe.VFSPipe
}

// Preconditions:
//   * fs.mu must be locked.
//   * rp.Mount().CheckBeginWrite() has been called successfully.
func (fs *filesystem) newNamedPipe(creds *auth.Credentials, mode linux.FileMode) *inode {
	file := &namedPipe{pipe: pipe.NewVFSPipe(pipe.DefaultPipeSize, usermem.PageSize)}
	file.inode.init(file, fs, creds, mode)
	file.inode.nlink = 1 // Only the parent has a link.
	return &file.inode
}

// namedPipeFD implements vfs.FileDescriptionImpl. Methods are implemented
// entirely via struct embedding.
type namedPipeFD struct {
	fileDescription

	*pipe.VFSPipeFD
}

func newNamedPipeFD(ctx context.Context, np *namedPipe, rp *vfs.ResolvingPath, vfsd *vfs.Dentry, flags uint32) (*vfs.FileDescription, error) {
	var err error
	var fd namedPipeFD
	fd.VFSPipeFD, err = np.pipe.NewVFSPipeFD(ctx, rp, vfsd, &fd.vfsfd, flags)
	if err != nil {
		return nil, err
	}
	mnt := rp.Mount()
	mnt.IncRef()
	vfsd.IncRef()
	fd.vfsfd.Init(&fd, mnt, vfsd)
	return &fd.vfsfd, nil
}
