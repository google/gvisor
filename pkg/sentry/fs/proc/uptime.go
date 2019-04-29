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

package proc

import (
	"fmt"
	"io"

	"gvisor.googlesource.com/gvisor/pkg/abi/linux"
	"gvisor.googlesource.com/gvisor/pkg/sentry/context"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs/fsutil"
	ktime "gvisor.googlesource.com/gvisor/pkg/sentry/kernel/time"
	"gvisor.googlesource.com/gvisor/pkg/sentry/usermem"
	"gvisor.googlesource.com/gvisor/pkg/syserror"
	"gvisor.googlesource.com/gvisor/pkg/waiter"
)

// uptime is a file containing the system uptime.
//
// +stateify savable
type uptime struct {
	fsutil.SimpleFileInode

	// The "start time" of the sandbox.
	startTime ktime.Time
}

// newUptime returns a new uptime file.
func newUptime(ctx context.Context, msrc *fs.MountSource) *fs.Inode {
	u := &uptime{
		SimpleFileInode: *fsutil.NewSimpleFileInode(ctx, fs.RootOwner, fs.FilePermsFromMode(0444), linux.PROC_SUPER_MAGIC),
		startTime:       ktime.NowFromContext(ctx),
	}
	return newProcInode(u, msrc, fs.SpecialFile, nil)
}

// GetFile implements fs.InodeOperations.GetFile.
func (u *uptime) GetFile(ctx context.Context, dirent *fs.Dirent, flags fs.FileFlags) (*fs.File, error) {
	return fs.NewFile(ctx, dirent, flags, &uptimeFile{startTime: u.startTime}), nil
}

// +stateify savable
type uptimeFile struct {
	waiter.AlwaysReady              `state:"nosave"`
	fsutil.FileGenericSeek          `state:"nosave"`
	fsutil.FileNoIoctl              `state:"nosave"`
	fsutil.FileNoMMap               `state:"nosave"`
	fsutil.FileNoopFlush            `state:"nosave"`
	fsutil.FileNoopFsync            `state:"nosave"`
	fsutil.FileNoopRelease          `state:"nosave"`
	fsutil.FileNotDirReaddir        `state:"nosave"`
	fsutil.FileNoWrite              `state:"nosave"`
	fsutil.FileUseInodeUnstableAttr `state:"nosave"`

	startTime ktime.Time
}

// Read implements fs.FileOperations.Read.
func (f *uptimeFile) Read(ctx context.Context, _ *fs.File, dst usermem.IOSequence, offset int64) (int64, error) {
	if offset < 0 {
		return 0, syserror.EINVAL
	}

	now := ktime.NowFromContext(ctx)
	// Pretend that we've spent zero time sleeping (second number).
	s := []byte(fmt.Sprintf("%.2f 0.00\n", now.Sub(f.startTime).Seconds()))
	if offset >= int64(len(s)) {
		return 0, io.EOF
	}

	n, err := dst.CopyOut(ctx, s[offset:])
	return int64(n), err
}
