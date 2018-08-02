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

package proc

import (
	"fmt"
	"io"

	"gvisor.googlesource.com/gvisor/pkg/sentry/context"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs/ramfs"
	ktime "gvisor.googlesource.com/gvisor/pkg/sentry/kernel/time"
	"gvisor.googlesource.com/gvisor/pkg/sentry/usermem"
	"gvisor.googlesource.com/gvisor/pkg/syserror"
)

// uptime is a file containing the system uptime.
//
// +stateify savable
type uptime struct {
	ramfs.Entry

	// The "start time" of the sandbox.
	startTime ktime.Time
}

// newUptime returns a new uptime file.
func (p *proc) newUptime(ctx context.Context, msrc *fs.MountSource) *fs.Inode {
	u := &uptime{
		startTime: ktime.NowFromContext(ctx),
	}
	u.InitEntry(ctx, fs.RootOwner, fs.FilePermsFromMode(0444))
	return newFile(u, msrc, fs.SpecialFile, nil)
}

// DeprecatedPreadv reads the current uptime.
func (u *uptime) DeprecatedPreadv(ctx context.Context, dst usermem.IOSequence, offset int64) (int64, error) {
	if offset < 0 {
		return 0, syserror.EINVAL
	}

	now := ktime.NowFromContext(ctx)
	// Pretend that we've spent zero time sleeping (second number).
	s := []byte(fmt.Sprintf("%.2f 0.00\n", now.Sub(u.startTime).Seconds()))
	if offset >= int64(len(s)) {
		return 0, io.EOF
	}

	n, err := dst.CopyOut(ctx, s[offset:])
	return int64(n), err
}
