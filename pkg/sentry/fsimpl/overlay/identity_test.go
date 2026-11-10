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

package overlay

import "testing"

func TestIdentityEncoding(t *testing.T) {
	fs := filesystem{dirDevMinor: 17}
	for _, tc := range []struct {
		name string
		key  layerDevNoAndIno
		want overlayIdentity
	}{
		{"first", layerDevNoAndIno{layerDevNumber{0, 1}, 1}, overlayIdentity{0, 17, 1<<16 | 1}},
		{"other_device", layerDevNoAndIno{layerDevNumber{0, 2}, 1}, overlayIdentity{0, 17, 1<<16 | 2}},
		{"largest_encoded", layerDevNoAndIno{layerDevNumber{0, 65535}, 1<<48 - 1}, overlayIdentity{0, 17, ^uint64(0)}},
		{"inode_overflow", layerDevNoAndIno{layerDevNumber{0, 1}, 1 << 48}, overlayIdentity{0, 1, 1 << 48}},
		{"largest_inode", layerDevNoAndIno{layerDevNumber{0, 1}, ^uint64(0)}, overlayIdentity{0, 1, ^uint64(0)}},
		{"device_overflow", layerDevNoAndIno{layerDevNumber{0, 1 << 16}, 1}, overlayIdentity{0, 1 << 16, 1}},
		{"nonanonymous_device", layerDevNoAndIno{layerDevNumber{8, 1}, 1}, overlayIdentity{8, 1, 1}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := fs.identityFor(tc.key); got != tc.want {
				t.Errorf("identityFor(%+v) = %+v, want %+v", tc.key, got, tc.want)
			}
		})
	}
}

func TestIdentityDoesNotRetainLookups(t *testing.T) {
	fs := filesystem{dirDevMinor: 17, dirInoCache: make(map[layerDevNoAndIno]*overlayOrigin)}
	for ino := uint64(1); ino <= 200000; ino++ {
		key := layerDevNoAndIno{layerDevNumber{0, 1}, ino}
		if got := fs.identityFor(key); got.ino != ino<<16|1 {
			t.Fatalf("identityFor(%+v) = %+v", key, got)
		}
	}
	if got := len(fs.dirInoCache); got != 0 {
		t.Errorf("retained %d identities after ordinary lookups", got)
	}
}

func TestIdentityOrigins(t *testing.T) {
	lower := layerDevNoAndIno{layerDevNumber{0, 1}, 42}
	upper := layerDevNoAndIno{layerDevNumber{0, 2}, 7}
	fs := filesystem{dirDevMinor: 17}
	want := fs.encodeIdentity(lower)
	fs.dirInoCache = map[layerDevNoAndIno]*overlayOrigin{
		upper: {identity: want},
	}
	if got := fs.identityFor(upper); got != want {
		t.Errorf("copy-up identity = %+v, want %+v", got, want)
	}
	if got := fs.identityFor(lower); got != want {
		t.Errorf("lower identity = %+v, want %+v", got, want)
	}
}

func TestIdentityEncodingDoesNotCollide(t *testing.T) {
	fs := filesystem{dirDevMinor: 17}
	seen := make(map[overlayIdentity]layerDevNoAndIno)
	for _, device := range []uint32{1, 2, 65535, 65536} {
		for _, ino := range []uint64{1, 1 << 32, 1<<48 - 1, 1 << 48, ^uint64(0)} {
			key := layerDevNoAndIno{layerDevNumber{0, device}, ino}
			id := fs.identityFor(key)
			if previous, ok := seen[id]; ok {
				t.Errorf("%+v and %+v map to %+v", previous, key, id)
			}
			seen[id] = key
		}
	}
}
