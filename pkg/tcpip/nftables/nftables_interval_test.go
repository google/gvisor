// Copyright 2026 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package nftables

import "testing"

// TestSetIntervalBackendEndpoints verifies interval membership when nft sends
// an interval as individual endpoints (start + NFT_SET_ELEM_INTERVAL_END), as
// it does for e.g. `add element allow4 { 140.82.112.0/20 }`.
func TestSetIntervalBackendEndpoints(t *testing.T) {
	b := &setIntervalBackend{keyLen: 4}
	// 140.82.112.0/20 == [140.82.112.0, 140.82.127.255]; nft sends the lower
	// sentinel (0.0.0.0 END), the start (140.82.112.0), and the exclusive upper
	// bound (140.82.128.0 END).
	adds := []struct {
		key []byte
		end bool
	}{
		{[]byte{0, 0, 0, 0}, true},
		{[]byte{140, 82, 112, 0}, false},
		{[]byte{140, 82, 128, 0}, true},
	}
	for i, a := range adds {
		if _, err := b.Add(&nftSetElem{startKey: a.key, intervalEnd: a.end}, i); err != nil {
			t.Fatalf("Add(%v, end=%t) failed: %v", a.key, a.end, err)
		}
	}
	for _, tc := range []struct {
		name string
		key  []byte
		want bool
	}{
		{"start is inclusive", []byte{140, 82, 112, 0}, true},
		{"inside range", []byte{140, 82, 120, 1}, true},
		{"last address in range", []byte{140, 82, 127, 255}, true},
		{"end is exclusive", []byte{140, 82, 128, 0}, false},
		{"below range", []byte{8, 8, 8, 8}, false},
		{"above range", []byte{200, 0, 0, 0}, false},
	} {
		if got := b.Find(tc.key) != -1; got != tc.want {
			t.Errorf("%s: Find(%v) member=%v, want %v", tc.name, tc.key, got, tc.want)
		}
	}
}

// TestSetIntervalBackendConcatRange verifies interval membership when an
// interval is expressed as a single element carrying an inclusive
// [startKey, endKey] range.
func TestSetIntervalBackendConcatRange(t *testing.T) {
	b := &setIntervalBackend{keyLen: 4}
	if _, err := b.Add(&nftSetElem{startKey: []byte{10, 0, 0, 0}, endKey: []byte{10, 0, 0, 255}}, 0); err != nil {
		t.Fatalf("Add range failed: %v", err)
	}
	for _, tc := range []struct {
		key  []byte
		want bool
	}{
		{[]byte{10, 0, 0, 0}, true},     // start inclusive
		{[]byte{10, 0, 0, 128}, true},   // middle
		{[]byte{10, 0, 0, 255}, true},   // end inclusive
		{[]byte{10, 0, 1, 0}, false},    // just above
		{[]byte{9, 255, 255, 255}, false}, // just below
	} {
		if got := b.Find(tc.key) != -1; got != tc.want {
			t.Errorf("Find(%v) member=%v, want %v", tc.key, got, tc.want)
		}
	}
}
