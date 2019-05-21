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

package ramfs

import (
	"gvisor.googlesource.com/gvisor/pkg/abi/linux"
	"gvisor.googlesource.com/gvisor/pkg/sentry/context"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs/fsutil"
	"gvisor.googlesource.com/gvisor/pkg/waiter"
)

// Symlink represents a symlink.
//
// +stateify savable
type Symlink struct {
	fsutil.InodeGenericChecker `state:"nosave"`
	fsutil.InodeNoopRelease    `state:"nosave"`
	fsutil.InodeNoopWriteOut   `state:"nosave"`
	fsutil.InodeNotAllocatable `state:"nosave"`
	fsutil.InodeNotDirectory   `state:"nosave"`
	fsutil.InodeNotMappable    `state:"nosave"`
	fsutil.InodeNotSocket      `state:"nosave"`
	fsutil.InodeNotTruncatable `state:"nosave"`
	fsutil.InodeVirtual        `state:"nosave"`

	fsutil.InodeSimpleAttributes
	fsutil.InodeSimpleExtendedAttributes

	// Target is the symlink target.
	Target string
}

var _ fs.InodeOperations = (*Symlink)(nil)

// NewSymlink returns a new Symlink.
func NewSymlink(ctx context.Context, owner fs.FileOwner, target string) *Symlink {
	// A symlink is assumed to always have permissions 0777.
	return &Symlink{
		InodeSimpleAttributes: fsutil.NewInodeSimpleAttributes(ctx, owner, fs.FilePermsFromMode(0777), linux.RAMFS_MAGIC),
		Target:                target,
	}
}

// UnstableAttr returns all attributes of this ramfs symlink.
func (s *Symlink) UnstableAttr(ctx context.Context, inode *fs.Inode) (fs.UnstableAttr, error) {
	uattr, err := s.InodeSimpleAttributes.UnstableAttr(ctx, inode)
	if err != nil {
		return fs.UnstableAttr{}, err
	}
	uattr.Size = int64(len(s.Target))
	uattr.Usage = uattr.Size
	return uattr, nil
}

// SetPermissions on a symlink is always rejected.
func (s *Symlink) SetPermissions(context.Context, *fs.Inode, fs.FilePermissions) bool {
	return false
}

// Readlink reads the symlink value.
func (s *Symlink) Readlink(ctx context.Context, _ *fs.Inode) (string, error) {
	s.NotifyAccess(ctx)
	return s.Target, nil
}

// Getlink returns ErrResolveViaReadlink, falling back to walking to the result
// of Readlink().
func (*Symlink) Getlink(context.Context, *fs.Inode) (*fs.Dirent, error) {
	return nil, fs.ErrResolveViaReadlink
}

// GetFile implements fs.FileOperations.GetFile.
func (s *Symlink) GetFile(ctx context.Context, dirent *fs.Dirent, flags fs.FileFlags) (*fs.File, error) {
	return fs.NewFile(ctx, dirent, flags, &symlinkFileOperations{}), nil
}

// +stateify savable
type symlinkFileOperations struct {
	fsutil.FileNoIoctl              `state:"nosave"`
	fsutil.FileNoMMap               `state:"nosave"`
	fsutil.FileNoRead               `state:"nosave"`
	fsutil.FileNoSeek               `state:"nosave"`
	fsutil.FileNoSplice             `state:"nosave"`
	fsutil.FileNoWrite              `state:"nosave"`
	fsutil.FileNoopFlush            `state:"nosave"`
	fsutil.FileNoopFsync            `state:"nosave"`
	fsutil.FileNoopRelease          `state:"nosave"`
	fsutil.FileNotDirReaddir        `state:"nosave"`
	fsutil.FileUseInodeUnstableAttr `state:"nosave"`
	waiter.AlwaysReady              `state:"nosave"`
}

var _ fs.FileOperations = (*symlinkFileOperations)(nil)
