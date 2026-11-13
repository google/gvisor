// Copyright 2026 The gVisor Authors.
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

//go:build !pagesize_64k

package pgalloc

import (
	"testing"

	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/sentry/usage"
)

// TestUncommittedRecycleZeroed verifies that an AllocateUncommitted that
// recycles waste pages returns them zeroed, as Allocate() promises.
func TestUncommittedRecycleZeroed(t *testing.T) {
	requireUsageInit(t)
	const allocLen = 2 * hostarch.PageSize

	f := newAccountingTestMemoryFile(t, MemoryFileOpts{MemoryAccounting: MemoryAccountingAllocated})

	// Allocate a range and fill it with a non-zero pattern.
	fr1, err := f.Allocate(allocLen, AllocOpts{Kind: usage.Anonymous, MemCgID: 1, Mode: AllocateUncommitted})
	if err != nil {
		t.Fatalf("Allocate() failed: %v", err)
	}
	f.forEachMappingSlice(fr1, func(bs []byte) {
		for i := range bs {
			bs[i] = 0xAA
		}
	})

	// Release the last reference to make the pages waste.
	f.DecRef(fr1)

	// An uncommitted allocation recycles the waste pages.
	fr2, err := f.Allocate(allocLen, AllocOpts{Kind: usage.Anonymous, MemCgID: 1, Mode: AllocateUncommitted})
	if err != nil {
		t.Fatalf("Allocate() failed: %v", err)
	}
	if fr2 != fr1 {
		t.Fatalf("Allocate() = %v; want recycled waste %v", fr2, fr1)
	}

	// The recycled pages must be zeroed.
	f.forEachMappingSlice(fr2, func(bs []byte) {
		for i, b := range bs {
			if b != 0 {
				t.Errorf("recycled uncommitted allocation %v has non-zero byte %d in slice %d = %#x; want 0", fr2, i, len(bs), b)
				return
			}
		}
	})
}
