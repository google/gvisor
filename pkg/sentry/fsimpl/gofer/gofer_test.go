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

package gofer

import (
	"sync/atomic"
	"testing"

	"gvisor.dev/gvisor/pkg/p9"
	"gvisor.dev/gvisor/pkg/sentry/contexttest"
	"gvisor.dev/gvisor/pkg/sentry/pgalloc"
)

func TestDestroyIdempotent(t *testing.T) {
	ctx := contexttest.Context(t)
	fs := filesystem{
		mfp: pgalloc.MemoryFileProviderFromContext(ctx),
		opts: filesystemOptions{
			// Test relies on no dentry being held in the cache.
			maxCachedDentries: 0,
		},
		syncableDentries: make(map[*dentry]struct{}),
		inoByQIDPath:     make(map[uint64]uint64),
		inoByKey:         make(map[inoKey]uint64),
	}

	attr := &p9.Attr{
		Mode: p9.ModeRegular,
	}
	mask := p9.AttrMask{
		Mode: true,
		Size: true,
	}
	parent, err := fs.newDentry(ctx, p9file{}, p9.QID{}, mask, attr)
	if err != nil {
		t.Fatalf("fs.newDentry(): %v", err)
	}

	child, err := fs.newDentry(ctx, p9file{}, p9.QID{}, mask, attr)
	if err != nil {
		t.Fatalf("fs.newDentry(): %v", err)
	}
	parent.cacheNewChildLocked(child, "child")

	fs.renameMu.Lock()
	defer fs.renameMu.Unlock()
	child.checkCachingLocked(ctx, true /* renameMuWriteLocked */)
	if got := atomic.LoadInt64(&child.refs); got != -1 {
		t.Fatalf("child.refs=%d, want: -1", got)
	}
	// Parent will also be destroyed when child reference is removed.
	if got := atomic.LoadInt64(&parent.refs); got != -1 {
		t.Fatalf("parent.refs=%d, want: -1", got)
	}
	child.checkCachingLocked(ctx, true /* renameMuWriteLocked */)
	child.checkCachingLocked(ctx, true /* renameMuWriteLocked */)
}
