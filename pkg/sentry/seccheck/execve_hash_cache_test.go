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

package seccheck

import (
	"bytes"
	"testing"
)

func TestExecveHashCache(t *testing.T) {
	opts := ExecveHashOptions{SHA256: true, SHA1: true}
	cache := NewExecveHashCache(DefaultExecveHashCacheCapacity, opts)

	key1 := ExecveKey{MountID: 1, Ino: 100, Size: 1024, MtimeSec: 10, MtimeNsec: 5}
	hash1 := ExecveHashes{
		SHA256: []byte("0123456789abcdef0123456789abcdef"),
		SHA1:   []byte("0123456789abcdef0123"),
	}

	// 1. Initial get should miss.
	if _, ok := cache.Lookup(key1); ok {
		t.Fatalf("expected cache miss on key1")
	}

	// 2. Add and get should hit.
	cache.Add(key1, hash1)
	got, ok := cache.Lookup(key1)
	if !ok || !bytes.Equal(got.SHA256, hash1.SHA256) || !bytes.Equal(got.SHA1, hash1.SHA1) {
		t.Fatalf("expected hit matching %v, got %v, ok: %v", hash1, got, ok)
	}

	// 3. Verify returned slice is a copy and partial updates merge cleanly.
	got.SHA256[0] = 'X'
	got2, _ := cache.Lookup(key1)
	if bytes.Equal(got2.SHA256, got.SHA256) {
		t.Fatalf("cache returned mutable reference")
	}

	cache.Add(key1, ExecveHashes{SHA1: []byte("99999999999999999999")})
	got3, _ := cache.Lookup(key1)
	if !bytes.Equal(got3.SHA256, hash1.SHA256) || !bytes.Equal(got3.SHA1, []byte("99999999999999999999")) {
		t.Fatalf("expected merged hashes after partial Add, got %v", got3)
	}

	// 4. Different mtime should miss.
	key1Modified := ExecveKey{MountID: 1, Ino: 100, Size: 1024, MtimeSec: 11, MtimeNsec: 5}
	if _, ok := cache.Lookup(key1Modified); ok {
		t.Fatalf("expected cache miss on key1Modified")
	}

	// 5. Eviction test.
	for i := 0; i < DefaultExecveHashCacheCapacity+10; i++ {
		k := ExecveKey{MountID: 2, Ino: uint64(i), Size: 100, MtimeSec: 1, MtimeNsec: 0}
		cache.Add(k, ExecveHashes{SHA256: []byte("dummy_hash_slice_thirty_two_bt")})
	}

	if len(cache.entries) > DefaultExecveHashCacheCapacity {
		t.Fatalf("cache entries exceeded max size: %d > %d", len(cache.entries), DefaultExecveHashCacheCapacity)
	}
	if cache.lru.Len() > DefaultExecveHashCacheCapacity {
		t.Fatalf("cache lru length exceeded max size: %d > %d", cache.lru.Len(), DefaultExecveHashCacheCapacity)
	}
	// Since key1 was added first and then entries were pushed beyond size, key1 should be evicted.
	if _, ok := cache.Lookup(key1); ok {
		t.Fatalf("expected key1 to be evicted")
	}
}

func TestExecveHashCacheConfigurable(t *testing.T) {
	opts := ExecveHashOptions{SHA256: true, SHA1: true}
	cache := NewExecveHashCache(3, opts)
	if got := cache.Capacity(); got != 3 {
		t.Fatalf("Capacity, want: 3, got: %d", got)
	}

	for i := 0; i < 5; i++ {
		k := ExecveKey{MountID: 3, Ino: uint64(i), Size: 50, MtimeSec: 1, MtimeNsec: 0}
		cache.Add(k, ExecveHashes{SHA256: []byte("dummy_hash_slice_thirty_two_bt")})
	}
	if len(cache.entries) > 3 || cache.lru.Len() > 3 {
		t.Fatalf("cache exceeded configured capacity 3: entries=%d lru=%d", len(cache.entries), cache.lru.Len())
	}

	// Verify disabled when capacity <= 0.
	disabledCache := NewExecveHashCache(0, opts)
	if got := disabledCache.Capacity(); got != 0 {
		t.Fatalf("Capacity, want: 0, got: %d", got)
	}

	k0 := ExecveKey{MountID: 3, Ino: 999, Size: 50, MtimeSec: 1, MtimeNsec: 0}
	disabledCache.Add(k0, ExecveHashes{SHA256: []byte("dummy_hash_slice_thirty_two_bt")})
	if len(disabledCache.entries) != 0 || disabledCache.lru.Len() != 0 {
		t.Fatalf("disabled cache should not add entries")
	}
	if _, ok := disabledCache.Lookup(k0); ok {
		t.Fatalf("expected cache miss when capacity <= 0")
	}
}
