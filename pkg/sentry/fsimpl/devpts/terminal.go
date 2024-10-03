// Copyright 2018 The gVisor Authors.
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

package devpts

import (
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

// Terminal is a pseudoterminal.
//
// Terminal implements kernel.TTYOperations.
//
// +stateify savable
type Terminal struct {
	// n is the terminal index. It is immutable.
	n uint32

	// ld is the line discipline of the terminal. It is immutable.
	ld *lineDiscipline

	// root is the rootInode for this devpts mount. It is immutable.
	root *rootInode

	// masterKTTY contains the controlling process of the master end of
	// this terminal. This field is immutable.
	masterKTTY *kernel.TTY

	// replicaKTTY contains the controlling process of the replica end of this
	// terminal. This field is immutable.
	replicaKTTY *kernel.TTY
}

var _ kernel.TTYOperations = (*Terminal)(nil)

// Open implements kernel.TTYOperations.Open.
func (t *Terminal) Open(ctx context.Context, mnt *vfs.Mount, vfsd *vfs.Dentry, opts vfs.OpenOptions) (*vfs.FileDescription, error) {
	tsk := kernel.TaskFromContext(ctx)
	if tsk == nil {
		return nil, linuxerr.EIO
	}
	t.root.mu.Lock()
	ri, ok := t.root.replicas[t.replicaKTTY.Index()]
	t.root.mu.Unlock()
	if !ok {
		return nil, linuxerr.EIO
	}
	fd := &replicaFileDescription{
		inode: ri,
	}
	fd.LockFD.Init(&ri.locks)
	if err := fd.vfsfd.Init(fd, opts.Flags, mnt, vfsd, &vfs.FileDescriptionOptions{}); err != nil {
		return nil, err
	}
	if opts.Flags&linux.O_NOCTTY == 0 {
		// Opening a replica sets the process' controlling TTY when
		// possible. An error indicates it cannot be set, and is
		// ignored silently. See Linux tty_open().
		_ = tsk.ThreadGroup().SetControllingTTY(ctx, t.replicaKTTY, false /* steal */, fd.vfsfd.IsReadable())
	}
	ri.t.ld.replicaOpen()
	return &fd.vfsfd, nil
}
