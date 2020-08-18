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

package dev

import (
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/rand"
	"gvisor.dev/gvisor/pkg/safemem"
	"gvisor.dev/gvisor/pkg/sentry/fs"
	"gvisor.dev/gvisor/pkg/sentry/fs/fsutil"
	"gvisor.dev/gvisor/pkg/usermem"
	"gvisor.dev/gvisor/pkg/waiter"
)

// +stateify savable
type randomDevice struct {
	fsutil.InodeGenericChecker       `state:"nosave"`
	fsutil.InodeNoExtendedAttributes `state:"nosave"`
	fsutil.InodeNoopAllocate         `state:"nosave"`
	fsutil.InodeNoopRelease          `state:"nosave"`
	fsutil.InodeNoopTruncate         `state:"nosave"`
	fsutil.InodeNoopWriteOut         `state:"nosave"`
	fsutil.InodeNotDirectory         `state:"nosave"`
	fsutil.InodeNotMappable          `state:"nosave"`
	fsutil.InodeNotSocket            `state:"nosave"`
	fsutil.InodeNotSymlink           `state:"nosave"`
	fsutil.InodeVirtual              `state:"nosave"`

	fsutil.InodeSimpleAttributes
}

var _ fs.InodeOperations = (*randomDevice)(nil)

func newRandomDevice(ctx context.Context, owner fs.FileOwner, mode linux.FileMode) *randomDevice {
	r := &randomDevice{
		InodeSimpleAttributes: fsutil.NewInodeSimpleAttributes(ctx, owner, fs.FilePermsFromMode(mode), linux.TMPFS_MAGIC),
	}
	return r
}

// GetFile implements fs.InodeOperations.GetFile.
func (*randomDevice) GetFile(ctx context.Context, dirent *fs.Dirent, flags fs.FileFlags) (*fs.File, error) {
	return fs.NewFile(ctx, dirent, flags, &randomFileOperations{}), nil
}

// +stateify savable
type randomFileOperations struct {
	fsutil.FileGenericSeek          `state:"nosave"`
	fsutil.FileNoIoctl              `state:"nosave"`
	fsutil.FileNoMMap               `state:"nosave"`
	fsutil.FileNoSplice             `state:"nosave"`
	fsutil.FileNoopFlush            `state:"nosave"`
	fsutil.FileNoopFsync            `state:"nosave"`
	fsutil.FileNoopRelease          `state:"nosave"`
	fsutil.FileNoopWrite            `state:"nosave"`
	fsutil.FileNotDirReaddir        `state:"nosave"`
	fsutil.FileUseInodeUnstableAttr `state:"nosave"`
	waiter.AlwaysReady              `state:"nosave"`
}

var _ fs.FileOperations = (*randomFileOperations)(nil)

// Read implements fs.FileOperations.Read.
func (*randomFileOperations) Read(ctx context.Context, _ *fs.File, dst usermem.IOSequence, _ int64) (int64, error) {
	return dst.CopyOutFrom(ctx, safemem.FromIOReader{rand.Reader})
}
