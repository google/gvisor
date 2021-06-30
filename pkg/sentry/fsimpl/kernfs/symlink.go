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

package kernfs

import (
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

// StaticSymlink provides an Inode implementation for symlinks that point to
// a immutable target.
//
// +stateify savable
type StaticSymlink struct {
	InodeAttrs
	InodeNoopRefCount
	InodeSymlink
	InodeNoStatFS

	target string
}

var _ Inode = (*StaticSymlink)(nil)

// NewStaticSymlink creates a new symlink file pointing to 'target'.
func NewStaticSymlink(ctx context.Context, creds *auth.Credentials, devMajor, devMinor uint32, ino uint64, target string) Inode {
	inode := &StaticSymlink{}
	inode.Init(ctx, creds, devMajor, devMinor, ino, target)
	return inode
}

// Init initializes the instance.
func (s *StaticSymlink) Init(ctx context.Context, creds *auth.Credentials, devMajor uint32, devMinor uint32, ino uint64, target string) {
	s.target = target
	s.InodeAttrs.Init(ctx, creds, devMajor, devMinor, ino, linux.ModeSymlink|0777)
}

// Readlink implements Inode.Readlink.
func (s *StaticSymlink) Readlink(_ context.Context, _ *vfs.Mount) (string, error) {
	return s.target, nil
}

// Getlink implements Inode.Getlink.
func (s *StaticSymlink) Getlink(context.Context, *vfs.Mount) (vfs.VirtualDentry, string, error) {
	return vfs.VirtualDentry{}, s.target, nil
}

// SetStat implements Inode.SetStat not allowing inode attributes to be changed.
func (*StaticSymlink) SetStat(context.Context, *vfs.Filesystem, *auth.Credentials, vfs.SetStatOptions) error {
	return linuxerr.EPERM
}
