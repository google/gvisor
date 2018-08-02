// Copyright 2018 Google Inc.
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

package ramfs

import (
	"sync"

	"gvisor.googlesource.com/gvisor/pkg/sentry/context"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs"
)

// Symlink represents a symlink.
//
// +stateify savable
type Symlink struct {
	Entry

	mu sync.Mutex `state:"nosave"`

	// Target is the symlink target.
	Target string
}

// InitSymlink initializes a symlink, pointing to the given target.
// A symlink is assumed to always have permissions 0777.
func (s *Symlink) InitSymlink(ctx context.Context, owner fs.FileOwner, target string) {
	s.InitEntry(ctx, owner, fs.FilePermsFromMode(0777))
	s.Target = target
}

// UnstableAttr returns all attributes of this ramfs symlink.
func (s *Symlink) UnstableAttr(ctx context.Context, inode *fs.Inode) (fs.UnstableAttr, error) {
	uattr, _ := s.Entry.UnstableAttr(ctx, inode)
	uattr.Size = int64(len(s.Target))
	uattr.Usage = uattr.Size
	return uattr, nil
}

// Check implements InodeOperations.Check.
func (s *Symlink) Check(ctx context.Context, inode *fs.Inode, p fs.PermMask) bool {
	return fs.ContextCanAccessFile(ctx, inode, p)
}

// SetPermissions on a symlink is always rejected.
func (s *Symlink) SetPermissions(context.Context, *fs.Inode, fs.FilePermissions) bool {
	return false
}

// Readlink reads the symlink value.
func (s *Symlink) Readlink(ctx context.Context, _ *fs.Inode) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.Entry.NotifyAccess(ctx)
	return s.Target, nil
}

// Getlink returns ErrResolveViaReadlink, falling back to walking to the result
// of Readlink().
func (*Symlink) Getlink(context.Context, *fs.Inode) (*fs.Dirent, error) {
	return nil, fs.ErrResolveViaReadlink
}
