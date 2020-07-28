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
	"gvisor.dev/gvisor/pkg/log"
	"sync/atomic"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

// dirFileFD is a directory file description in fuse.
type dirFileFD struct {
	fileDescription
}

// IterDirents implements FileDescriptionImpl.IterDirents.
func (dir *dirFileFD) IterDirents(ctx context.Context, callback vfs.IterDirentsCallback) error {
	fusefs := dir.inode().fs
	task, creds := kernel.TaskFromContext(ctx), auth.CredentialsFromContext(ctx)

	in := linux.FUSEReadIn{
		Fh:     dir.Fh,
		Offset: uint64(atomic.LoadInt64(&dir.off)),
		Size:   linux.FUSE_PAGE_SIZE,
		Flags:  dir.statusFlags(),
	}

	/// TODO(gVisor.dev/issue/3404): Support FUSE_READDIRPLUS.
	req, err := fusefs.conn.NewRequest(creds, uint32(task.ThreadID()), dir.inode().NodeID, linux.FUSE_READDIR, &in)
	if err != nil {
		return err
	}

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
		nextOff := int64(fuseDirent.Meta.Off) + 1
		dirent := vfs.Dirent{
			Name:    fuseDirent.Name,
			Type:    uint8(fuseDirent.Meta.Type),
			Ino:     fuseDirent.Meta.Ino,
			NextOff: nextOff,
		}
		log.Infof("fusefs.DirFile.IterDirents: %v file found", dirent.Name)
		if err := callback.Handle(dirent); err != nil {
			return err
		}
		atomic.StoreInt64(&dir.off, nextOff)
	}

	return nil
}
