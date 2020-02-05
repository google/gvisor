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

package gofer

import (
	"sync/atomic"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	ktime "gvisor.dev/gvisor/pkg/sentry/kernel/time"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

func dentryTimestampFromP9(s, ns uint64) int64 {
	return int64(s*1e9 + ns)
}

func dentryTimestampFromStatx(ts linux.StatxTimestamp) int64 {
	return ts.Sec*1e9 + int64(ts.Nsec)
}

func statxTimestampFromDentry(ns int64) linux.StatxTimestamp {
	return linux.StatxTimestamp{
		Sec:  ns / 1e9,
		Nsec: uint32(ns % 1e9),
	}
}

func nowFromContext(ctx context.Context) (int64, bool) {
	if clock := ktime.RealtimeClockFromContext(ctx); clock != nil {
		return clock.Now().Nanoseconds(), true
	}
	return 0, false
}

// Preconditions: fs.interop != InteropModeShared.
func (d *dentry) touchAtime(ctx context.Context, mnt *vfs.Mount) {
	if err := mnt.CheckBeginWrite(); err != nil {
		return
	}
	now, ok := nowFromContext(ctx)
	if !ok {
		mnt.EndWrite()
		return
	}
	d.metadataMu.Lock()
	atomic.StoreInt64(&d.atime, now)
	d.metadataMu.Unlock()
	mnt.EndWrite()
}

// Preconditions: fs.interop != InteropModeShared. The caller has successfully
// called vfs.Mount.CheckBeginWrite().
func (d *dentry) touchCMtime(ctx context.Context) {
	now, ok := nowFromContext(ctx)
	if !ok {
		return
	}
	d.metadataMu.Lock()
	atomic.StoreInt64(&d.mtime, now)
	atomic.StoreInt64(&d.ctime, now)
	d.metadataMu.Unlock()
}
