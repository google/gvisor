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

package linux

import (
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/fspath"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

func copyInPath(t *kernel.Task, addr hostarch.Addr) (fspath.Path, error) {
	pathname, err := t.CopyInString(addr, linux.PATH_MAX)
	if err != nil {
		return fspath.Path{}, err
	}
	return fspath.Parse(pathname), nil
}

type taskPathOperation struct {
	pop          vfs.PathOperation
	haveStartRef bool
}

func getTaskPathOperation(t *kernel.Task, dirfd int32, path fspath.Path, emptyPathCheck shouldAllowEmptyPathType, shouldFollowFinalSymlink shouldFollowFinalSymlink) (taskPathOperation, error) {
	root := t.FSContext().RootDirectory()
	start := root
	haveStartRef := false
	if !path.Absolute {
		if !path.HasComponents() && !emptyPathCheck.allow() {
			root.DecRef(t)
			return taskPathOperation{}, linuxerr.ENOENT
		}
		if dirfd == linux.AT_FDCWD {
			start = t.FSContext().WorkingDirectory()
			haveStartRef = true
		} else {
			dirfile := t.GetFile(dirfd)
			if dirfile == nil {
				root.DecRef(t)
				return taskPathOperation{}, linuxerr.EBADF
			}
			defer dirfile.DecRef(t)

			// AT_EMPTY_PATH is allowed only if t's creds are identical to the creds under which the FD was
			// opened, or if t has CAP_DAC_READ_SEARCH in those creds' userns.
			// Similar to how Linux handles LOOKUP_LINKAT_EMPTY in path_init() in fs/namei.c.
			if emptyPathCheck == allowEmptyPathWithCredsCheck {
				if dirfile.Credentials() != t.Credentials() && !t.HasCapabilityIn(linux.CAP_DAC_READ_SEARCH, dirfile.Credentials().UserNamespace) {
					root.DecRef(t)
					return taskPathOperation{}, linuxerr.ENOENT
				}
			}

			start = dirfile.VirtualDentry()
			start.IncRef()
			haveStartRef = true
		}
	}
	return taskPathOperation{
		pop: vfs.PathOperation{
			Root:               root,
			Start:              start,
			Path:               path,
			FollowFinalSymlink: bool(shouldFollowFinalSymlink),
		},
		haveStartRef: haveStartRef,
	}, nil
}

func (tpop *taskPathOperation) Release(t *kernel.Task) {
	tpop.pop.Root.DecRef(t)
	if tpop.haveStartRef {
		tpop.pop.Start.DecRef(t)
		tpop.haveStartRef = false
	}
}

type shouldAllowEmptyPathType uint8

const (
	disallowEmptyPath shouldAllowEmptyPathType = iota
	allowEmptyPath
	allowEmptyPathWithCredsCheck
)

func (sa shouldAllowEmptyPathType) allow() bool {
	return sa != disallowEmptyPath
}

func shouldAllowEmptyPath(allow bool) shouldAllowEmptyPathType {
	if allow {
		return allowEmptyPath
	}
	return disallowEmptyPath
}

type shouldFollowFinalSymlink bool

const (
	nofollowFinalSymlink shouldFollowFinalSymlink = false
	followFinalSymlink   shouldFollowFinalSymlink = true
)
