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

package proc

import (
	"fmt"
	"strconv"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/sentry/context"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/kernfs"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/syserror"
)

type selfSymlink struct {
	kernfs.InodeAttrs
	kernfs.InodeNoopRefCount
	kernfs.InodeSymlink

	pidns *kernel.PIDNamespace
}

var _ kernfs.Inode = (*selfSymlink)(nil)

func newSelfSymlink(creds *auth.Credentials, ino uint64, perm linux.FileMode, pidns *kernel.PIDNamespace) *kernfs.Dentry {
	inode := &selfSymlink{pidns: pidns}
	inode.Init(creds, ino, linux.ModeSymlink|perm)

	d := &kernfs.Dentry{}
	d.Init(inode)
	return d
}

func (s *selfSymlink) Readlink(ctx context.Context) (string, error) {
	t := kernel.TaskFromContext(ctx)
	if t == nil {
		// Who is reading this link?
		return "", syserror.EINVAL
	}
	tgid := s.pidns.IDOfThreadGroup(t.ThreadGroup())
	if tgid == 0 {
		return "", syserror.ENOENT
	}
	return strconv.FormatUint(uint64(tgid), 10), nil
}

type threadSelfSymlink struct {
	kernfs.InodeAttrs
	kernfs.InodeNoopRefCount
	kernfs.InodeSymlink

	pidns *kernel.PIDNamespace
}

var _ kernfs.Inode = (*threadSelfSymlink)(nil)

func newThreadSelfSymlink(creds *auth.Credentials, ino uint64, perm linux.FileMode, pidns *kernel.PIDNamespace) *kernfs.Dentry {
	inode := &threadSelfSymlink{pidns: pidns}
	inode.Init(creds, ino, linux.ModeSymlink|perm)

	d := &kernfs.Dentry{}
	d.Init(inode)
	return d
}

func (s *threadSelfSymlink) Readlink(ctx context.Context) (string, error) {
	t := kernel.TaskFromContext(ctx)
	if t == nil {
		// Who is reading this link?
		return "", syserror.EINVAL
	}
	tgid := s.pidns.IDOfThreadGroup(t.ThreadGroup())
	tid := s.pidns.IDOfTask(t)
	if tid == 0 || tgid == 0 {
		return "", syserror.ENOENT
	}
	return fmt.Sprintf("%d/task/%d", tgid, tid), nil
}
