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

package dev

import (
	"gvisor.googlesource.com/gvisor/pkg/abi/linux"
	"gvisor.googlesource.com/gvisor/pkg/sentry/context"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs/fsutil"
	"gvisor.googlesource.com/gvisor/pkg/sentry/usermem"
	"gvisor.googlesource.com/gvisor/pkg/syserror"
	"gvisor.googlesource.com/gvisor/pkg/waiter"
)

// fullDevice is used to implement /dev/full.
//
// +stateify savable
type fullDevice struct {
	fsutil.InodeGenericChecker       `state:"nosave"`
	fsutil.InodeNoExtendedAttributes `state:"nosave"`
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

var _ fs.InodeOperations = (*fullDevice)(nil)

func newFullDevice(ctx context.Context, owner fs.FileOwner, mode linux.FileMode) *fullDevice {
	f := &fullDevice{
		InodeSimpleAttributes: fsutil.NewInodeSimpleAttributes(ctx, owner, fs.FilePermsFromMode(mode), linux.TMPFS_MAGIC),
	}
	return f
}

// GetFile implements fs.InodeOperations.GetFile.
func (f *fullDevice) GetFile(ctx context.Context, dirent *fs.Dirent, flags fs.FileFlags) (*fs.File, error) {
	flags.Pread = true
	return fs.NewFile(ctx, dirent, flags, &fullFileOperations{}), nil
}

// +stateify savable
type fullFileOperations struct {
	waiter.AlwaysReady       `state:"nosave"`
	fsutil.FileGenericSeek   `state:"nosave"`
	fsutil.FileNoIoctl       `state:"nosave"`
	fsutil.FileNoMMap        `state:"nosave"`
	fsutil.FileNoopFlush     `state:"nosave"`
	fsutil.FileNoopFsync     `state:"nosave"`
	fsutil.FileNoopRelease   `state:"nosave"`
	fsutil.FileNotDirReaddir `state:"nosave"`
	readZeros                `state:"nosave"`
}

var _ fs.FileOperations = (*fullFileOperations)(nil)

// Write implements FileOperations.Write.
func (fullFileOperations) Write(context.Context, *fs.File, usermem.IOSequence, int64) (int64, error) {
	return 0, syserror.ENOSPC
}
