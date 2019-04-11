// Copyright 2018 Google LLC
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
	"gvisor.googlesource.com/gvisor/pkg/sentry/socket/unix/transport"
	"gvisor.googlesource.com/gvisor/pkg/waiter"
)

// Socket represents a socket.
//
// +stateify savable
type Socket struct {
	fsutil.InodeGenericChecker `state:"nosave"`
	fsutil.InodeNoopRelease    `state:"nosave"`
	fsutil.InodeNoopWriteOut   `state:"nosave"`
	fsutil.InodeNotDirectory   `state:"nosave"`
	fsutil.InodeNotMappable    `state:"nosave"`
	fsutil.InodeNotSymlink     `state:"nosave"`
	fsutil.InodeNotTruncatable `state:"nosave"`
	fsutil.InodeVirtual        `state:"nosave"`

	fsutil.InodeSimpleAttributes
	fsutil.InodeSimpleExtendedAttributes

	// ep is the bound endpoint.
	ep transport.BoundEndpoint
}

var _ fs.InodeOperations = (*Socket)(nil)

// NewSocket returns a new Socket.
func NewSocket(ctx context.Context, ep transport.BoundEndpoint, owner fs.FileOwner, perms fs.FilePermissions) *Socket {
	return &Socket{
		InodeSimpleAttributes: fsutil.NewInodeSimpleAttributes(ctx, owner, perms, linux.SOCKFS_MAGIC),
		ep:                    ep,
	}
}

// BoundEndpoint returns the socket data.
func (s *Socket) BoundEndpoint(*fs.Inode, string) transport.BoundEndpoint {
	// ramfs only supports stored sentry internal sockets. Only gofer sockets
	// care about the path argument.
	return s.ep
}

// GetFile implements fs.FileOperations.GetFile.
func (s *Socket) GetFile(ctx context.Context, dirent *fs.Dirent, flags fs.FileFlags) (*fs.File, error) {
	return fs.NewFile(ctx, dirent, flags, &socketFileOperations{}), nil
}

// +stateify savable
type socketFileOperations struct {
	waiter.AlwaysReady              `state:"nosave"`
	fsutil.FileNoIoctl              `state:"nosave"`
	fsutil.FileNoMMap               `state:"nosave"`
	fsutil.FileNoopFlush            `state:"nosave"`
	fsutil.FileNoopFsync            `state:"nosave"`
	fsutil.FileNoopRelease          `state:"nosave"`
	fsutil.FileNoRead               `state:"nosave"`
	fsutil.FileNoSeek               `state:"nosave"`
	fsutil.FileNotDirReaddir        `state:"nosave"`
	fsutil.FileNoWrite              `state:"nosave"`
	fsutil.FileUseInodeUnstableAttr `state:"nosave"`
}

var _ fs.FileOperations = (*socketFileOperations)(nil)
