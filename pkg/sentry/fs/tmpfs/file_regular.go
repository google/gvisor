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

package tmpfs

import (
	"gvisor.googlesource.com/gvisor/pkg/sentry/context"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs/fsutil"
	"gvisor.googlesource.com/gvisor/pkg/sentry/memmap"
	"gvisor.googlesource.com/gvisor/pkg/sentry/usermem"
	"gvisor.googlesource.com/gvisor/pkg/waiter"
)

// regularFileOperations implements fs.FileOperations for a regular
// tmpfs file.
type regularFileOperations struct {
	waiter.AlwaysReady   `state:"nosave"`
	fsutil.NoopRelease   `state:"nosave"`
	fsutil.GenericSeek   `state:"nosave"`
	fsutil.NotDirReaddir `state:"nosave"`
	fsutil.NoopFsync     `state:"nosave"`
	fsutil.NoopFlush     `state:"nosave"`
	fsutil.NoIoctl       `state:"nosave"`

	// iops is the InodeOperations of a regular tmpfs file. It is
	// guaranteed to be the same as file.Dirent.Inode.InodeOperations,
	// see operations that take fs.File below.
	iops *fileInodeOperations
}

// Read implements fs.FileOperations.Read.
func (r *regularFileOperations) Read(ctx context.Context, file *fs.File, dst usermem.IOSequence, offset int64) (int64, error) {
	return r.iops.read(ctx, dst, offset)
}

// Write implements fs.FileOperations.Write.
func (r *regularFileOperations) Write(ctx context.Context, file *fs.File, src usermem.IOSequence, offset int64) (int64, error) {
	return r.iops.write(ctx, src, offset)
}

// ConfigureMMap implements fs.FileOperations.ConfigureMMap.
func (r *regularFileOperations) ConfigureMMap(ctx context.Context, file *fs.File, opts *memmap.MMapOpts) error {
	return fsutil.GenericConfigureMMap(file, r.iops, opts)
}
