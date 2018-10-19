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
	"gvisor.googlesource.com/gvisor/pkg/rand"
	"gvisor.googlesource.com/gvisor/pkg/sentry/context"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs/ramfs"
	"gvisor.googlesource.com/gvisor/pkg/sentry/safemem"
	"gvisor.googlesource.com/gvisor/pkg/sentry/usermem"
)

// +stateify savable
type randomDevice struct {
	ramfs.Entry
}

func newRandomDevice(ctx context.Context, owner fs.FileOwner, mode linux.FileMode) *randomDevice {
	r := &randomDevice{}
	r.InitEntry(ctx, owner, fs.FilePermsFromMode(mode))
	return r
}

// DeprecatedPreadv reads random data.
func (*randomDevice) DeprecatedPreadv(ctx context.Context, dst usermem.IOSequence, offset int64) (int64, error) {
	return dst.CopyOutFrom(ctx, safemem.FromIOReader{rand.Reader})
}

// DeprecatedPwritev implements fs.HandleOperations.DeprecatedPwritev.
func (*randomDevice) DeprecatedPwritev(ctx context.Context, src usermem.IOSequence, offset int64) (int64, error) {
	// On Linux, "Writing to /dev/random or /dev/urandom will update the
	// entropy pool with the data written, but this will not result in a higher
	// entropy count" - random(4). We don't need to support this, but we do
	// need to support the write, so just make it a no-op a la /dev/null.
	return src.NumBytes(), nil
}

// Truncate should be simply ignored for character devices on linux.
func (r *randomDevice) Truncate(context.Context, *fs.Inode, int64) error {
	return nil
}
