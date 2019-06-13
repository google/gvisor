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

package ext4

import (
	"gvisor.googlesource.com/gvisor/pkg/sentry/context"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs/fsutil"
	"gvisor.googlesource.com/gvisor/pkg/sentry/usermem"
	"gvisor.googlesource.com/gvisor/pkg/waiter"
)

// fileOperations implements fs.FileOperations.
//
// +stateify savable
type fileOperations struct {
	fsutil.FileGenericSeek          `state:"nosave"`
	fsutil.FileNoopRelease          `state:"nosave"`
	fsutil.FileUseInodeUnstableAttr `state:"nosave"`
	waiter.AlwaysReady              `state:"nosave"`

	// TODO(b/134676337): Implement the below.
	fsutil.FileNoMMap    `state:"nosave"`
	fsutil.FileNoWrite   `state:"nosave"`
	fsutil.FileNoopFsync `state:"nosave"`
	fsutil.FileNoopFlush `state:"nosave"`
	// Ext4 supports splice(2) in read and write mode.
	fsutil.FileNoSplice `state:"nosplice"`
	// Ext4 supports some ioctls. See fs/ext4/ioctl.c.
	fsutil.FileNoIoctl `state:"nosave"`

	// inodeOperations is the inodeOperations backing the file. It is protected
	// by a reference held by File.Dirent.Inode which is stable until
	// FileOperations.Release is called.
	inodeOperations *inodeOperations `state:"wait"`
}

// Read implements fs.FileOperations.Read.
func (f *fileOperations) Read(ctx context.Context, file *fs.File, dst usermem.IOSequence, offset int64) (int64, error) {
	panic("unimplemented")
}

// Readdir implements fs.FileOperations.Readdir.
func (f *fileOperations) Readdir(ctx context.Context, file *fs.File, serializer fs.DentrySerializer) (int64, error) {
	panic("unimplemented")
}
