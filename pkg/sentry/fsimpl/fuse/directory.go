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

package fuse

import (
	"sync/atomic"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/usermem"
)

type directoryFD struct {
	fileDescription
	vfs.NoSpliceInFD
}

// Allocate implements directoryFD.Allocate.
func (*directoryFD) Allocate(ctx context.Context, mode, offset, length uint64) error {
	return linuxerr.EISDIR
}

// PRead implements vfs.FileDescriptionImpl.PRead.
func (*directoryFD) PRead(ctx context.Context, dst usermem.IOSequence, offset int64, opts vfs.ReadOptions) (int64, error) {
	return 0, linuxerr.EISDIR
}

// Read implements vfs.FileDescriptionImpl.Read.
func (*directoryFD) Read(ctx context.Context, dst usermem.IOSequence, opts vfs.ReadOptions) (int64, error) {
	return 0, linuxerr.EISDIR
}

// PWrite implements vfs.FileDescriptionImpl.PWrite.
func (*directoryFD) PWrite(ctx context.Context, src usermem.IOSequence, offset int64, opts vfs.WriteOptions) (int64, error) {
	return 0, linuxerr.EISDIR
}

// Write implements vfs.FileDescriptionImpl.Write.
func (*directoryFD) Write(ctx context.Context, src usermem.IOSequence, opts vfs.WriteOptions) (int64, error) {
	return 0, linuxerr.EISDIR
}

// IterDirents implements vfs.FileDescriptionImpl.IterDirents.
func (dir *directoryFD) IterDirents(ctx context.Context, callback vfs.IterDirentsCallback) error {
	fusefs := dir.inode().fs
	task, creds := kernel.TaskFromContext(ctx), auth.CredentialsFromContext(ctx)

	in := linux.FUSEReadIn{
		Fh:     dir.Fh,
		Offset: uint64(atomic.LoadInt64(&dir.off)),
		Size:   linux.FUSE_PAGE_SIZE,
		Flags:  dir.statusFlags(),
	}

	// TODO(gVisor.dev/issue/3404): Support FUSE_READDIRPLUS.
	req := fusefs.conn.NewRequest(creds, uint32(task.ThreadID()), dir.inode().nodeID, linux.FUSE_READDIR, &in)
	res, err := fusefs.conn.Call(task, req)
	if err != nil {
		return err
	}
	if err := res.Error(); err != nil {
		return err
	}

	var out linux.FUSEDirents
	if err := res.UnmarshalPayload(&out); err != nil {
		return err
	}

	for _, fuseDirent := range out.Dirents {
		nextOff := int64(fuseDirent.Meta.Off)
		dirent := vfs.Dirent{
			Name:    fuseDirent.Name,
			Type:    uint8(fuseDirent.Meta.Type),
			Ino:     fuseDirent.Meta.Ino,
			NextOff: nextOff,
		}

		if err := callback.Handle(dirent); err != nil {
			return err
		}
		atomic.StoreInt64(&dir.off, nextOff)
	}

	return nil
}
