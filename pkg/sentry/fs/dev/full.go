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

package dev

import (
	"math"

	"gvisor.googlesource.com/gvisor/pkg/abi/linux"
	"gvisor.googlesource.com/gvisor/pkg/sentry/context"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs/ramfs"
	"gvisor.googlesource.com/gvisor/pkg/sentry/usermem"
	"gvisor.googlesource.com/gvisor/pkg/syserror"
)

// fullDevice is used to implement /dev/full.
//
// +stateify savable
type fullDevice struct {
	ramfs.Entry
}

func newFullDevice(ctx context.Context, owner fs.FileOwner, mode linux.FileMode) *fullDevice {
	f := &fullDevice{}
	f.InitEntry(ctx, owner, fs.FilePermsFromMode(mode))
	return f
}

// DeprecatedPwritev implements fs.InodeOperations.DeprecatedPwritev by
// returining ENOSPC.
func (f *fullDevice) DeprecatedPwritev(_ context.Context, _ usermem.IOSequence, _ int64) (int64, error) {
	return 0, syserror.ENOSPC
}

// DeprecatedPreadv implements fs.InodeOperations.DeprecatedPreadv.
func (f *fullDevice) DeprecatedPreadv(ctx context.Context, dst usermem.IOSequence, _ int64) (int64, error) {
	return dst.ZeroOut(ctx, math.MaxInt64)
}

// Truncate should be simply ignored for character devices on linux.
func (f *fullDevice) Truncate(context.Context, *fs.Inode, int64) error {
	return nil
}
